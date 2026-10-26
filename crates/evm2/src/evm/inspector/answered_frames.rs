//! Transaction-level regression coverage for inspector answers and EIP-8037.

use super::*;
use crate::{
    SpecId,
    env::BlockEnvExt,
    ethereum::{TxEnvelope, ethereum_tx_registry},
    evm::{AccountInfo, InMemoryDB, TxResult},
    interpreter::{GasTracker, InstrStop, MessageResultExt, op},
    test_utils::{legacy_bytecode, push_all},
    utils::address_to_word,
};
use alloc::{boxed::Box, vec::Vec};
use alloy_consensus::{TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, TxKind, U256};

const CALLER: Address = Address::repeat_byte(0x11);
const PARENT: Address = Address::repeat_byte(0x22);
const ANSWERED: Address = Address::repeat_byte(0x33);
const CAP: u64 = 1 << 24;
const RESERVOIR: u64 = 1_000_000;
const STATE: u64 = 120 * 1530;
// EIP-2780 base plus a cold recipient access; CREATE uses CREATE_ACCESS instead.
const CALL_INTRINSIC: u64 = 12_000 + 3000;
const VALUE_INTRINSIC: u64 = CALL_INTRINSIC + 6000;
const CREATE_INTRINSIC: u64 = 12_000 + 12_000;
const CHILD_LIMIT: u64 = 50_000;

struct Answer {
    naive: bool,
    top: bool,
    stop: InstrStop,
    address: Option<Address>,
    rewrite: Option<(InstrStop, Option<Address>)>,
    opcode: u8,
    before: Option<(u64, u64)>,
    after: Option<(u64, u64)>,
    inherited: Vec<(u64, u64)>,
    ends: usize,
}

impl Answer {
    fn new(naive: bool, stop: InstrStop) -> Self {
        Self {
            naive,
            top: false,
            stop,
            address: None,
            rewrite: None,
            opcode: 0,
            before: None,
            after: None,
            inherited: Vec::new(),
            ends: 0,
        }
    }
}

impl Inspector<crate::BaseEvmTypes> for Answer {
    fn step(&mut self, interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>) {
        self.opcode = interp.opcode();
        if matches!(self.opcode, op::CALL | op::CREATE) {
            self.before = Some((interp.gas().remaining(), interp.gas().reservoir()));
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>) {
        if matches!(self.opcode, op::CALL | op::CREATE) {
            self.after = Some((interp.gas().remaining(), interp.gas().reservoir()));
        }
    }

    fn call(
        &mut self,
        _interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>,
        message: &mut Message,
    ) -> Option<MessageResult> {
        if (message.depth == 0) != self.top {
            return None;
        }
        self.inherited.push((message.gas_limit, message.reservoir));
        Some(MessageResultExt {
            stop: self.stop,
            gas: if self.naive {
                GasTracker::new(message.gas_limit)
            } else {
                GasTracker::new_with_execution_gas_and_reservoir(
                    message.gas_limit,
                    message.reservoir,
                )
            },
            created_address: self.address,
            ..Default::default()
        })
    }

    fn create(
        &mut self,
        interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>,
        message: &mut Message,
    ) -> Option<MessageResult> {
        self.call(interp, message)
    }

    fn call_end(
        &mut self,
        _interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>,
        message: &Message,
        result: &mut MessageResult,
    ) {
        if (message.depth == 0) == self.top {
            self.ends += 1;
            if let Some((stop, address)) = self.rewrite {
                result.stop = stop;
                result.created_address = address;
            }
        }
    }

    fn create_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>,
        message: &Message,
        result: &mut MessageResult,
    ) {
        self.call_end(interp, message, result);
    }
}

fn call_code(value: u64) -> Vec<u8> {
    let mut code = Vec::new();
    push_all(
        &mut code,
        [
            U256::ZERO,
            U256::ZERO,
            U256::ZERO,
            U256::ZERO,
            U256::from(value),
            address_to_word(&ANSWERED),
            U256::from(CHILD_LIMIT),
        ],
    );
    code.extend([op::CALL, op::STOP]);
    code
}

fn create_code() -> Vec<u8> {
    let mut code = Vec::new();
    push_all(&mut code, [U256::ZERO; 3]);
    code.extend([op::CREATE, op::STOP]);
    code
}

fn run(
    spec: SpecId,
    code: Vec<u8>,
    kind: TxKind,
    value: u64,
    reservoir: u64,
    answer: Answer,
) -> (TxResult, Box<Answer>) {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        &CALLER,
        AccountInfo::default().with_balance(U256::from(1_000_000_000u64)),
    );
    db.insert_account_info(
        &PARENT,
        AccountInfo {
            balance: U256::from(10),
            nonce: 1,
            code: Some(legacy_bytecode(code)),
            ..Default::default()
        },
    );
    let mut evm = crate::Evm::<crate::BaseEvmTypes>::new(
        spec,
        BlockEnvExt::default(),
        ethereum_tx_registry(spec),
        db,
        crate::Precompiles::base(spec),
    );
    evm.set_inspector(answer);
    let tx = Recovered::new_unchecked(
        TxEnvelope::Legacy(TxLegacy {
            to: kind,
            value: U256::from(value),
            gas_limit: CAP + reservoir,
            ..Default::default()
        }),
        CALLER,
    );
    let result = evm.transact(&tx).unwrap().discard();
    (result, evm.clear_inspector_as::<Answer>().unwrap())
}

#[test]
fn naive_answers_lose_reservoir() {
    // These deliberately naive answers reproduce the defect on unchanged main.
    for (code, value, regular, charge) in [
        (call_code(0), 0, CALL_INTRINSIC + 7 * 3 + 3000, 0),
        (call_code(1), 0, CALL_INTRINSIC + 7 * 3 + 3000 + 9000, STATE),
        (create_code(), 0, CALL_INTRINSIC + 3 * 3 + 12_000, STATE),
    ] {
        let create = code[code.len() - 2] == op::CREATE;
        for stop in [InstrStop::Stop, InstrStop::Revert] {
            let mut answer = Answer::new(true, stop);
            answer.address = create.then_some(PARENT.create(1));
            let (result, inspector) = run(
                SpecId::AMSTERDAM,
                code.clone(),
                TxKind::Call(PARENT),
                value,
                RESERVOIR,
                answer,
            );
            let kept = if stop.is_success() { charge } else { 0 };
            assert_eq!(inspector.before.unwrap().1, RESERVOIR);
            assert_eq!(inspector.after.unwrap().1, if stop.is_success() { 0 } else { charge });
            assert_eq!(result.tx_gas_used(), regular + RESERVOIR - charge + kept);
            assert_eq!(result.state_gas_spent, kept);
        }
    }
    for (kind, value, intrinsic, charge) in [
        (TxKind::Call(PARENT), 0, CALL_INTRINSIC, 0),
        (TxKind::Call(ANSWERED), 1, VALUE_INTRINSIC, STATE),
        (TxKind::Create, 0, CREATE_INTRINSIC, STATE),
    ] {
        for stop in [InstrStop::Return, InstrStop::Revert] {
            let mut answer = Answer::new(true, stop);
            answer.top = true;
            answer.address = matches!(kind, TxKind::Create).then_some(CALLER.create(0));
            let (result, _) = run(SpecId::AMSTERDAM, Vec::new(), kind, value, RESERVOIR, answer);
            let kept = if stop.is_success() { charge } else { 0 };
            assert_eq!(result.tx_gas_used(), intrinsic + RESERVOIR - charge + kept);
            assert_eq!(result.state_gas_spent, kept);
        }
    }
}
