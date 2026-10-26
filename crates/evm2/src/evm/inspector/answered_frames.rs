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
use alloy_primitives::{Address, Bytes, TxKind, U256};

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
        let answer = MessageResultExt::new_answer(message, self.stop, Bytes::new(), self.address);
        if self.naive {
            Some(MessageResultExt { gas: GasTracker::new(message.gas_limit), ..answer })
        } else {
            Some(answer)
        }
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

fn run<I: Inspector<crate::BaseEvmTypes> + 'static>(
    spec: SpecId,
    code: Vec<u8>,
    kind: TxKind,
    value: u64,
    reservoir: u64,
    answer: I,
) -> (TxResult, Box<I>) {
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
    (result, evm.clear_inspector_as::<I>().unwrap())
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

fn assert_inner_answer(
    create: bool,
    value: u64,
    reservoir: u64,
    stop: InstrStop,
    address: Option<Address>,
    rewrite: Option<(InstrStop, Option<Address>)>,
) {
    let mut answer = Answer::new(false, stop);
    answer.address = address;
    answer.rewrite = rewrite;
    let (result, inspector) = run(
        SpecId::AMSTERDAM,
        if create { create_code() } else { call_code(value) },
        TxKind::Call(PARENT),
        0,
        reservoir,
        answer,
    );
    let (final_stop, final_address) = rewrite.unwrap_or((stop, address));
    let charge = if create || value != 0 { STATE } else { 0 };
    let kept =
        if final_stop.is_success() && (!create || final_address.is_some()) { charge } else { 0 };
    let spilled = charge.saturating_sub(reservoir);
    let pushes = if create { 3 * 3 } else { 7 * 3 };
    let opcode_cost = if create { 12_000 } else { 3000 + 9000 * value };
    let available = CAP - CALL_INTRINSIC - pushes - opcode_cost - spilled;
    let child_limit = if create { available - available / 64 } else { CHILD_LIMIT + 2300 * value };
    let consumed = if final_stop.is_halt() { child_limit } else { 0 };
    let case = (create, value, reservoir, stop, address, rewrite);
    assert!(result.status, "{case:?}: {result:?}");
    assert_eq!(inspector.ends, 1, "{case:?}");
    assert_eq!(inspector.inherited, [(child_limit, reservoir.saturating_sub(charge))], "{case:?}");
    let before = inspector.before.unwrap();
    let after = inspector.after.unwrap();
    assert_eq!(before, (CAP - CALL_INTRINSIC - pushes, reservoir), "{case:?}");
    assert_eq!(after.1, reservoir.saturating_sub(kept), "{case:?}");
    let kept_spill = if kept != 0 { spilled } else { 0 };
    assert_eq!(before.0 - after.0, opcode_cost + kept_spill + consumed, "{case:?}");
    assert_eq!(
        result.tx_gas_used(),
        CALL_INTRINSIC + pushes + opcode_cost + kept + consumed,
        "{case:?}"
    );
    assert_eq!(result.state_gas_spent, kept, "{case:?}");
}

#[test]
fn inner_call_answers_preserve_reservoir_and_settle_state_charge() {
    for value in [0, 1] {
        for stop in [InstrStop::Stop, InstrStop::Revert, InstrStop::OutOfGas] {
            assert_inner_answer(false, value, RESERVOIR, stop, None, None);
        }
    }
}

#[test]
fn inner_create_answers_settle_by_stop_and_address() {
    for stop in [InstrStop::Stop, InstrStop::Return, InstrStop::Revert, InstrStop::OutOfGas] {
        for address in [None, Some(PARENT.create(1))] {
            assert_inner_answer(true, 0, RESERVOIR, stop, address, None);
        }
    }
}

#[test]
fn end_hooks_rewrite_answers_before_single_settlement() {
    for create in [false, true] {
        for stop in [InstrStop::Return, InstrStop::Revert, InstrStop::OutOfGas] {
            for rewritten in [InstrStop::Return, InstrStop::Revert, InstrStop::OutOfGas] {
                for address in [None, Some(PARENT.create(1))] {
                    for final_address in [None, Some(PARENT.create(1))] {
                        assert_inner_answer(
                            create,
                            u64::from(!create),
                            RESERVOIR,
                            stop,
                            address,
                            Some((rewritten, final_address)),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn upfront_state_charge_spills_into_execution_gas() {
    for reservoir in [0, STATE / 2] {
        for stop in [InstrStop::Return, InstrStop::Revert, InstrStop::OutOfGas] {
            assert_inner_answer(false, 1, reservoir, stop, None, None);
            for address in [None, Some(PARENT.create(1))] {
                assert_inner_answer(true, 0, reservoir, stop, address, None);
            }
        }
    }
}

#[test]
fn first_frame_answers_preserve_reservoir_and_refund_failed_charges() {
    for reservoir in [RESERVOIR, STATE / 2, 0] {
        for (kind, value, intrinsic, charge) in [
            (TxKind::Call(PARENT), 0, CALL_INTRINSIC, 0),
            (TxKind::Call(ANSWERED), 1, VALUE_INTRINSIC, STATE),
            (TxKind::Create, 0, CREATE_INTRINSIC, STATE),
        ] {
            for stop in [InstrStop::Stop, InstrStop::Return, InstrStop::Revert, InstrStop::OutOfGas]
            {
                for address in [None, Some(CALLER.create(0))] {
                    if kind == TxKind::Create && stop.is_success() && address.is_none() {
                        continue;
                    }
                    // Test both the direct answer and an end-hook rewrite to each final result.
                    for initial in [
                        None,
                        Some(InstrStop::Return),
                        Some(InstrStop::Revert),
                        Some(InstrStop::OutOfGas),
                    ] {
                        let mut answer = Answer::new(false, initial.unwrap_or(stop));
                        answer.top = true;
                        answer.address = address;
                        if initial.is_some() {
                            answer.address = None;
                            answer.rewrite = Some((stop, address));
                        }
                        let (result, inspector) =
                            run(SpecId::AMSTERDAM, Vec::new(), kind, value, reservoir, answer);
                        let spilled = charge.saturating_sub(reservoir);
                        let kept = if stop.is_success() { charge } else { 0 };
                        let expected = if stop.is_halt() { CAP } else { intrinsic + kept };
                        let case = (reservoir, kind, stop, address, initial);
                        assert_eq!(
                            inspector.inherited,
                            [(CAP - intrinsic - spilled, reservoir.saturating_sub(charge))],
                            "{case:?}"
                        );
                        assert_eq!(inspector.ends, 1, "{case:?}");
                        assert_eq!(result.status, stop.is_success(), "{case:?}");
                        assert_eq!(result.tx_gas_used(), expected, "{case:?}");
                        assert_eq!(result.state_gas_spent, kept, "{case:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn before_amsterdam_answers_equal_naive_gas() {
    for create in [false, true] {
        for top in [false, true] {
            for stop in [InstrStop::Return, InstrStop::Revert, InstrStop::OutOfGas] {
                let code = if create { create_code() } else { call_code(1) };
                let kind = if top {
                    if create { TxKind::Create } else { TxKind::Call(ANSWERED) }
                } else {
                    TxKind::Call(PARENT)
                };
                let run_case = |naive| {
                    let mut answer = Answer::new(naive, stop);
                    answer.top = top;
                    answer.address = create.then_some(CALLER.create(0));
                    run(SpecId::OSAKA, code.clone(), kind, u64::from(top), 0, answer).0
                };
                let result = run_case(false);
                assert_eq!(result, run_case(true));
                let regular = if top {
                    if create { 21_000 + 32_000 } else { 21_000 }
                } else if create {
                    21_000 + 3 * 3 + 32_000
                } else {
                    21_000 + 7 * 3 + 2600 + 9000 - 2300 + 25_000
                };
                let expected = if stop.is_halt() {
                    if top {
                        CAP
                    } else if create {
                        let available = CAP - regular;
                        regular + available - available / 64
                    } else {
                        regular + CHILD_LIMIT + 2300
                    }
                } else {
                    regular
                };
                assert_eq!(result.tx_gas_used(), expected);
                assert_eq!(result.state_gas_spent, 0);
            }
        }
    }
}

#[test]
fn accounted_execution_answer_and_end_hook_gas_are_preserved() {
    struct Executed;

    impl Inspector<crate::BaseEvmTypes> for Executed {
        fn call(
            &mut self,
            _interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>,
            message: &mut Message,
        ) -> Option<MessageResult> {
            if message.depth == 0 {
                return None;
            }
            // Stand in for execution whose state and gas were accounted elsewhere.
            let mut gas = GasTracker::new_with_execution_gas_and_reservoir(
                message.gas_limit,
                message.reservoir,
            );
            gas.spend(1234).unwrap();
            gas.spend_state(5678).unwrap();
            Some(MessageResultExt { stop: InstrStop::Return, gas, ..Default::default() })
        }

        fn call_end(
            &mut self,
            _interp: &mut Interpreter<'_, '_, crate::BaseEvmTypes>,
            message: &Message,
            result: &mut MessageResult,
        ) {
            if message.depth != 0 {
                result.gas.spend(17).unwrap();
            }
        }
    }

    let (result, _) =
        run(SpecId::AMSTERDAM, call_code(0), TxKind::Call(PARENT), 0, RESERVOIR, Executed);
    assert_eq!(result.tx_gas_used(), CALL_INTRINSIC + 7 * 3 + 3000 + 1234 + 5678 + 17);
    assert_eq!(result.state_gas_spent, 5678);
}
