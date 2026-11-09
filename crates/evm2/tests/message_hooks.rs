//! `MessageHooks` run for every message, on the plain and the inspected path alike, and can stop
//! a start or take back a success answer before evm2 commits it.

use alloy_primitives::{Address, Bytes, U256};
use evm2::{
    BaseEvmConfigSelector, Evm, EvmFeatures, EvmTypesHost, ExecutionConfig, MessageHooks,
    NoopInspector, SpecId, Version,
    bytecode::Bytecode,
    env::BlockEnv,
    evm::{AccountInfo, InMemoryDB},
    interpreter::{
        GasTracker, Host, InstrStop, Message, MessageExt, MessageKind, MessageResult, op,
    },
    precompiles::Precompiles,
    registry::TxRegistry,
};

struct Types;
impl EvmTypesHost for Types {
    type ConfigSelector = BaseEvmConfigSelector;
    type SpecId = SpecId;
    type Tx = ();
    type EvmExt = Vec<String>;
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = ();
    type BlockEnvExt = ();
    type Host<'a> = Evm<'a, Self>;
    type MessageHooks = Recorder;
}

const PARENT: Address = Address::with_last_byte(0xaa);
const CODE: Address = Address::with_last_byte(0xc0);
const EMPTY: Address = Address::with_last_byte(0xe0);
const IDENTITY: Address = Address::with_last_byte(0x04);
/// A creation whose code deposit the hook refuses with a revert, without checking its gas.
const REFUSED: Address = Address::with_last_byte(0xa3);

/// Value-calls `to` with all gas; stores the success word at slot `slot`.
fn call(code: &mut Vec<u8>, to: Address, slot: u8) {
    code.extend([op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH1, 1, op::PUSH20]);
    code.extend_from_slice(to.as_slice());
    code.extend([op::GAS, op::CALL, op::PUSH1, slot, op::SSTORE]);
}

fn evm() -> Evm<'static, Types> {
    let mut parent = Vec::new();
    call(&mut parent, CODE, 1);
    call(&mut parent, EMPTY, 2);
    call(&mut parent, IDENTITY, 3);
    parent.push(op::STOP);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        &PARENT,
        AccountInfo::default()
            .with_balance(U256::from(10))
            .with_code(Bytecode::new_legacy(Bytes::from(parent))),
    );
    db.insert_account_info(
        &CODE,
        AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(&[op::STOP]))),
    );
    Evm::new_with_ext(
        SpecId::PRAGUE,
        BlockEnv::<Types>::default(),
        TxRegistry::new(),
        db,
        Precompiles::base(SpecId::PRAGUE),
        Vec::new(),
    )
}

/// Records every hook call; stops every value-call start to an account without code and takes
/// back the precompile's success answer.
#[derive(Debug, Default)]
struct Recorder;

impl MessageHooks<Types> for Recorder {
    fn enter(evm: &mut Evm<'_, Types>, m: &Message<Types>) {
        evm.ext_mut().push(format!("enter {}", m.call_target));
    }

    fn unsettled(evm: &mut Evm<'_, Types>, m: &Message<Types>, _: &MessageResult<Types>) {
        evm.ext_mut().push(format!("unsettled {}", m.call_target));
    }

    fn exit(
        evm: &mut Evm<'_, Types>,
        m: &Message<Types>,
        r: &Result<MessageResult<Types>, evm2::ExecutionError>,
    ) {
        evm.ext_mut().push(format!("exit {} {}", m.call_target, r.is_ok()));
    }

    fn before(
        evm: &mut Evm<'_, Types>,
        m: &mut Message<Types>,
    ) -> Result<Option<MessageResult<Types>>, evm2::ExecutionError> {
        evm.ext_mut().push(format!("before {}", m.call_target));
        if m.call_target == Address::with_last_byte(0xfe) {
            evm.state_mut().account(&PARENT)?.bump_nonce();
            return Err(evm2::ExecutionError::Fatal("hook error".into()));
        }
        Ok(None)
    }

    fn started(
        evm: &mut Evm<'_, Types>,
        m: &Message<Types>,
    ) -> Result<Option<(InstrStop, Bytes)>, evm2::ExecutionError> {
        evm.ext_mut().push(format!("started {}", m.call_target));
        Ok((m.call_target == EMPTY).then(|| (InstrStop::Revert, Bytes::from_static(b"stop"))))
    }

    fn frame_built(evm: &mut Evm<'_, Types>, m: &Message<Types>, _: &mut GasTracker) {
        evm.ext_mut().push(format!("built {}", m.call_target));
    }

    fn before_commit(
        evm: &mut Evm<'_, Types>,
        m: &Message<Types>,
        stop: &mut InstrStop,
        out: &mut Bytes,
        gas: &mut GasTracker,
    ) -> Result<(), evm2::ExecutionError> {
        evm.ext_mut().push(format!("before_commit {} {stop:?}", m.call_target));
        if let Some((remaining, cost)) = gas.failed_charge() {
            evm.ext_mut().push(format!("failed {remaining} {cost}"));
        }
        if m.call_target == IDENTITY && stop.is_success() {
            *stop = InstrStop::Revert;
            *out = Bytes::from_static(b"taken back");
        }
        if matches!(*stop, InstrStop::OutOfFunds | InstrStop::CreateCollision) {
            *out = Bytes::from_static(b"seen");
        }
        Ok(())
    }

    fn admit_code_deposit(
        _: &mut Evm<'_, Types>,
        m: &Message<Types>,
        _: &Bytes,
        before: &GasTracker,
        gas: &mut evm2::interpreter::Gas,
    ) -> Result<Option<(InstrStop, Bytes)>, evm2::ExecutionError> {
        if m.destination == Address::with_last_byte(0xa2) {
            assert_eq!(before.remaining(), 292);
            assert_eq!(gas.remaining(), 92);
            return Ok(Some((InstrStop::Revert, Bytes::from_static(b"refused"))));
        }
        if m.destination == REFUSED {
            return Ok(Some((InstrStop::Revert, Bytes::from_static(b"refused"))));
        }
        Ok(None)
    }

    fn after(
        evm: &mut Evm<'_, Types>,
        m: &Message<Types>,
        r: &mut MessageResult<Types>,
    ) -> Result<(), evm2::ExecutionError> {
        evm.ext_mut().push(format!("after {} {:?}", m.call_target, r.stop));
        Ok(())
    }
}

fn run(inspect: bool) -> (Vec<String>, [U256; 3], U256, U256) {
    let mut evm = evm();
    if inspect {
        evm.set_inspector(NoopInspector::default());
    }
    let code = evm.state_mut().account(&PARENT).unwrap().load_code().unwrap();
    let mut message: Message<Types> = MessageExt {
        kind: MessageKind::Call,
        gas_limit: 1_000_000,
        destination: PARENT,
        call_target: PARENT,
        caller: Address::with_last_byte(0xee),
        code,
        code_address: PARENT,
        ..MessageExt::default()
    };
    let result = Host::execute_message(&mut evm, &mut message).unwrap();
    assert_eq!(result.stop, InstrStop::Stop);
    let slots = [1u64, 2, 3]
        .map(|k| evm.state_mut().storage_slot_untracked(&PARENT, &U256::from(k)).unwrap());
    let bal = |evm: &mut Evm<'_, Types>, a| {
        evm.state_mut().account_info_untracked(&a).unwrap().map_or(U256::ZERO, |i| i.balance)
    };
    let (empty, identity) = (bal(&mut evm, EMPTY), bal(&mut evm, IDENTITY));
    let log = evm.ext().clone();
    (log, slots, empty, identity)
}

#[test]
fn hooks_run_for_every_message_on_both_paths() {
    let (plain, slots, empty, identity) = run(false);
    let (inspected, slots_i, empty_i, identity_i) = run(true);
    assert_eq!(plain, inspected, "the inspected path runs the same hooks");
    assert_eq!((slots, empty, identity), (slots_i, empty_i, identity_i));
    // The call with code succeeded; the start to the empty account was stopped (its value moved
    // back); the precompile's success answer was taken back (its value moved back too).
    assert_eq!(slots, [U256::from(1), U256::ZERO, U256::ZERO]);
    assert_eq!((empty, identity), (U256::ZERO, U256::ZERO));
    // Every message reached before/started/before_commit/after; only frames with code were built.
    for target in [PARENT, CODE, EMPTY, IDENTITY] {
        assert!(plain.iter().any(|l| *l == format!("before {target}")), "{target}");
        assert!(plain.iter().any(|l| l.starts_with(&format!("after {target}"))), "{target}");
    }
    assert!(plain.contains(&format!("built {CODE}")));
    assert!(
        !plain.contains(&format!("built {EMPTY}")) && !plain.contains(&format!("built {IDENTITY}"))
    );
    assert!(plain.contains(&format!("before_commit {IDENTITY} Return")));
    assert!(
        plain.contains(&format!("after {EMPTY} Revert"))
            && plain.contains(&format!("after {IDENTITY} Revert"))
    );
}

struct Answer;
impl evm2::Inspector<Types> for Answer {
    fn call(
        &mut self,
        _: &mut evm2::interpreter::Interpreter<'_, '_, Types>,
        _: &mut Message<Types>,
    ) -> Option<MessageResult<Types>> {
        Some(MessageResult::<Types>::default())
    }
}

#[test]
fn inspector_answers_pair_observers_without_running_consensus_hooks() {
    let mut evm = evm();
    evm.set_inspector(Answer);
    let mut message = Message::<Types>::default();
    Host::execute_message(&mut evm, &mut message).unwrap();
    assert_eq!(
        evm.ext(),
        &[format!("enter {}", Address::ZERO), format!("exit {} true", Address::ZERO),]
    );
}

#[test]
fn halted_messages_run_no_hooks_on_either_path() {
    for inspected in [false, true] {
        let mut evm = evm();
        if inspected {
            evm.set_inspector(NoopInspector::default());
        }
        let mut message = Message::<Types> {
            gas_limit: 100,
            destination: CODE,
            call_target: CODE,
            ..Default::default()
        };
        let halted = MessageResult::<Types> { stop: InstrStop::OutOfGas, ..Default::default() };
        let result = evm.execute_halted_message(&mut message, halted).unwrap();
        assert_eq!(result.stop, InstrStop::OutOfGas, "inspected={inspected}");
        assert!(evm.ext().is_empty(), "inspected={inspected}: {:?}", evm.ext());
    }
}

#[test]
fn hook_errors_roll_back_state_and_pair_observers() {
    let mut evm = evm();
    let target = Address::with_last_byte(0xfe);
    let mut message = Message::<Types> { call_target: target, ..Default::default() };
    let result = Host::execute_message(&mut evm, &mut message);
    assert!(matches!(result, Err(evm2::ExecutionError::Fatal(_))));
    assert_eq!(evm.state_mut().account(&PARENT).unwrap().get().unwrap().nonce, 0);
    assert_eq!(
        evm.ext(),
        &[format!("enter {target}"), format!("before {target}"), format!("exit {target} false"),]
    );
}

/// Runs `message` on a fresh EVM, plain or with an inspector, and returns its result and the log.
fn run_message(
    inspected: bool,
    mut message: Message<Types>,
) -> (MessageResult<Types>, Vec<String>, Evm<'static, Types>) {
    let mut evm = evm();
    if inspected {
        evm.set_inspector(NoopInspector::default());
    }
    let result = Host::execute_message(&mut evm, &mut message).unwrap();
    let log = evm.ext().clone();
    (result, log, evm)
}

#[test]
fn out_of_funds_call_reaches_before_commit_on_both_paths() {
    for inspected in [false, true] {
        let message = Message::<Types> {
            kind: MessageKind::Call,
            gas_limit: 1_000,
            destination: CODE,
            call_target: CODE,
            caller: PARENT,
            value: U256::from(11),
            ..Default::default()
        };
        let (result, log, mut evm) = run_message(inspected, message);
        assert_eq!(result.stop, InstrStop::OutOfFunds, "inspected={inspected}");
        assert!(log.contains(&format!("before_commit {CODE} OutOfFunds")), "{log:?}");
        assert_eq!(result.output.as_ref(), b"seen", "the hook's rewrite is the result");
        assert_eq!(result.gas.remaining(), 1_000, "an out-of-funds answer keeps its gas");
        let balance = evm.state_mut().account_info_untracked(&PARENT).unwrap().unwrap().balance;
        assert_eq!(balance, U256::from(10), "nothing moved");
    }
}

/// A creation whose address already holds code fails after its checkpoint: the failure is a
/// built-in post-checkpoint result, so it reaches `before_commit` like a call's out-of-funds
/// answer, and the start (the created address's warming aside) is rolled back.
#[test]
fn create_collision_reaches_before_commit_on_both_paths() {
    for inspected in [false, true] {
        let message = Message::<Types> {
            kind: MessageKind::Create,
            gas_limit: 1_000,
            destination: CODE,
            call_target: CODE,
            caller: PARENT,
            code: Bytecode::new_legacy(Bytes::from_static(&[op::STOP])),
            ..Default::default()
        };
        let (result, log, mut evm) = run_message(inspected, message);
        assert_eq!(result.stop, InstrStop::CreateCollision, "inspected={inspected}");
        assert!(log.contains(&format!("before_commit {CODE} CreateCollision")), "{log:?}");
        assert!(!log.contains(&format!("started {CODE}")), "the start was not made: {log:?}");
        assert!(!log.contains(&format!("built {CODE}")), "no frame was built: {log:?}");
        assert_eq!(result.output.as_ref(), b"seen", "the hook's rewrite is the result");
        assert_eq!(result.created_address, None);
        let code = evm.state_mut().account(&CODE).unwrap().load_code().unwrap();
        assert_eq!(code.original_byte_slice(), &[op::STOP], "the occupied account is untouched");
    }
}

fn deploy(evm: &mut Evm<'_, Types>, address: Address, gas: u64) -> MessageResult<Types> {
    deploy_with_reservoir(evm, address, gas, 0)
}

/// Deploys the one byte `0x00` from `PUSH1 1; PUSH0; RETURN` (8 of execution gas).
fn deploy_with_reservoir(
    evm: &mut Evm<'_, Types>,
    address: Address,
    gas: u64,
    reservoir: u64,
) -> MessageResult<Types> {
    let mut message = Message::<Types> {
        kind: MessageKind::Create,
        destination: address,
        call_target: address,
        caller: PARENT,
        gas_limit: gas,
        reservoir,
        code: Bytecode::new_legacy(Bytes::from_static(&[op::PUSH1, 1, op::PUSH0, op::RETURN])),
        ..Default::default()
    };
    Host::execute_message(evm, &mut message).unwrap()
}

#[test]
fn code_admission_revert_restores_predeposit_gas_and_rolls_back_creation() {
    let mut evm = evm();
    let address = Address::with_last_byte(0xa2);
    let result = deploy(&mut evm, address, 300);
    assert_eq!(result.stop, InstrStop::Revert);
    assert_eq!(result.output.as_ref(), b"refused");
    assert_eq!(result.gas.remaining(), 292);
    assert_eq!(result.created_address, None);
    assert!(evm.state_mut().account(&address).unwrap().get().is_none());
}

/// Amsterdam, where a code deposit costs keccak word gas and state gas, with the reservoir-only
/// rule on or off.
fn amsterdam_evm(reservoir_refills: bool) -> Evm<'static, Types> {
    let mut version = Version::new(SpecId::AMSTERDAM);
    version.features.set(EvmFeatures::EIP8037_RESERVOIR_REFILLS, reservoir_refills);
    let mut db = InMemoryDB::default();
    db.insert_account_info(&PARENT, AccountInfo::default());
    Evm::new_with_execution_config_and_ext(
        ExecutionConfig::for_spec_and_version(SpecId::AMSTERDAM, version),
        SpecId::AMSTERDAM,
        BlockEnv::<Types>::default(),
        TxRegistry::new(),
        db,
        Precompiles::base(SpecId::AMSTERDAM),
        Vec::new(),
    )
}

/// The refused deposit of one byte charges 6 of hashing and 1,530 of state gas. EIP-8037's rule
/// restores the gas from before the deposit; the reservoir-only rule keeps the hashing spent and
/// gives the state charge back into the reservoir, whichever pool paid it.
#[test]
fn code_admission_revert_under_the_reservoir_only_rule_gives_the_deposit_state_gas_to_the_reservoir()
 {
    const HASHING: u64 = 6;
    const DEPOSIT_STATE: u64 = 1_530;
    for (reservoir, refills, remaining, reservoir_left) in [
        (0, false, 100_000 - 8, 0),
        (5_000, false, 100_000 - 8, 5_000),
        (0, true, 100_000 - 8 - HASHING - DEPOSIT_STATE, DEPOSIT_STATE),
        (5_000, true, 100_000 - 8 - HASHING, 5_000),
    ] {
        let mut evm = amsterdam_evm(refills);
        let result = deploy_with_reservoir(&mut evm, REFUSED, 100_000, reservoir);
        let case = format!("reservoir={reservoir} refills={refills}");
        assert_eq!(result.stop, InstrStop::Revert, "{case}");
        assert_eq!(result.output.as_ref(), b"refused", "{case}");
        assert_eq!(
            (result.gas.remaining(), result.gas.reservoir()),
            (remaining, reservoir_left),
            "{case}"
        );
        assert_eq!(result.gas.state_gas_spent(), 0, "{case}");
        assert_eq!(result.created_address, None, "{case}");
        assert!(evm.state_mut().account(&REFUSED).unwrap().get().is_none(), "{case}");
    }
}

/// Steps every opcode, so an inspected run takes the inspect table, which zeroes `remaining` on an
/// out-of-gas step. `NoopInspector` steps nothing and runs the plain loop.
struct Stepping;

impl evm2::Inspector<Types> for Stepping {}

#[test]
fn failed_static_debit_survives_inspector_zeroing_without_changing_settlement() {
    for inspected in [false, true] {
        let mut evm = evm();
        if inspected {
            evm.set_inspector(Stepping);
        }
        let mut message = Message::<Types> {
            gas_limit: 2,
            destination: CODE,
            call_target: CODE,
            code: Bytecode::new_legacy(Bytes::from_static(&[op::PUSH1, 0])),
            ..Default::default()
        };
        let result = Host::execute_message(&mut evm, &mut message).unwrap();
        assert_eq!(result.stop, InstrStop::OutOfGas, "inspected={inspected}");
        assert_eq!(result.gas.remaining(), 0);
        assert_eq!(result.gas.failed_charge(), Some((2, 3)));
        assert!(evm.ext().iter().any(|s| s == "failed 2 3"));
    }
}

/// A call's input is a range of the caller's memory, and every message hook runs while the caller
/// is the running frame, so [`Evm::message_input`] reads it. [`MessageHooks::before`] gets the
/// message by `&mut` and may keep its input, so the message path gives it the input as owned
/// bytes, which stay right after the caller overwrites its memory and grows it into a new
/// allocation.
mod kept_input {
    use super::*;
    use evm2::interpreter::MessageInput;

    struct Types;
    impl EvmTypesHost for Types {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = Seen;
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = ();
        type Host<'a> = Evm<'a, Self>;
        type MessageHooks = Keeper;
    }

    /// What the hooks saw of the inner message's input.
    #[derive(Debug, Default)]
    struct Seen {
        /// Whether `enter` saw a range of the caller's memory, and the bytes it read.
        entered: Option<(bool, Vec<u8>)>,
        /// Whether `before` saw owned bytes, and the bytes it read.
        before: Option<(bool, Vec<u8>)>,
        /// The input `before` kept.
        kept: Option<MessageInput>,
        /// What the callee returned: its input.
        returned: Option<Bytes>,
    }

    /// Notes and keeps the input of every inner message.
    struct Keeper;
    impl MessageHooks<Types> for Keeper {
        fn enter(evm: &mut Evm<'_, Types>, m: &Message<Types>) {
            if m.depth > 0 {
                let seen = (m.input.as_owned().is_none(), evm.message_input(m).to_vec());
                evm.ext_mut().entered = Some(seen);
            }
        }

        fn before(
            evm: &mut Evm<'_, Types>,
            m: &mut Message<Types>,
        ) -> Result<Option<MessageResult<Types>>, evm2::ExecutionError> {
            if m.depth > 0 {
                let seen = (m.input.as_owned().is_some(), evm.message_input(m).to_vec());
                evm.ext_mut().before = Some(seen);
                evm.ext_mut().kept = Some(m.input.clone());
            }
            Ok(None)
        }

        fn after(
            evm: &mut Evm<'_, Types>,
            m: &Message<Types>,
            r: &mut MessageResult<Types>,
        ) -> Result<(), evm2::ExecutionError> {
            if m.depth > 0 {
                evm.ext_mut().returned = Some(r.output.clone());
            }
            Ok(())
        }
    }

    /// Stores `byte` over memory 0..32.
    fn fill(code: &mut Vec<u8>, byte: u8) {
        code.push(op::PUSH32);
        code.extend([byte; 32]);
        code.extend([op::PUSH0, op::MSTORE]);
    }

    #[test]
    fn hooks_read_the_callers_bytes_and_before_keeps_them_past_an_overwrite_and_a_growth() {
        let mut parent = Vec::new();
        fill(&mut parent, 0xaa);
        // CALL(gas, CODE, 0, 0, 32, 0, 0): memory 0..32 is the input.
        parent.extend([op::PUSH0, op::PUSH0, op::PUSH1, 32, op::PUSH0, op::PUSH0, op::PUSH20]);
        parent.extend_from_slice(CODE.as_slice());
        parent.extend([op::GAS, op::CALL, op::POP]);
        fill(&mut parent, 0xbb);
        // MSTORE8(1 << 16, 0): grows memory from 32 bytes past 64 KiB, which moves it.
        parent.extend([op::PUSH0, op::PUSH3, 1, 0, 0, op::MSTORE8, op::STOP]);
        // CALLDATACOPY(0, 0, CALLDATASIZE); RETURN(0, CALLDATASIZE): returns its input.
        let echo = [
            op::CALLDATASIZE,
            op::PUSH0,
            op::PUSH0,
            op::CALLDATACOPY,
            op::CALLDATASIZE,
            op::PUSH0,
            op::RETURN,
        ];
        for inspected in [false, true] {
            let mut db = InMemoryDB::default();
            let code = Bytecode::new_legacy(Bytes::copy_from_slice(&echo));
            db.insert_account_info(&CODE, AccountInfo::default().with_code(code));
            let mut evm = Evm::<Types>::new_with_ext(
                SpecId::PRAGUE,
                BlockEnv::<Types>::default(),
                TxRegistry::new(),
                db,
                Precompiles::base(SpecId::PRAGUE),
                Seen::default(),
            );
            if inspected {
                evm.set_inspector(NoopInspector::default());
            }
            let mut message: Message<Types> = MessageExt {
                kind: MessageKind::Call,
                gas_limit: 1_000_000,
                destination: PARENT,
                call_target: PARENT,
                code: Bytecode::new_legacy(Bytes::from(parent.clone())),
                code_address: PARENT,
                ..MessageExt::default()
            };
            let result = Host::execute_message(&mut evm, &mut message).unwrap();
            assert_eq!(result.stop, InstrStop::Stop, "inspected={inspected}");
            let seen = evm.ext();
            let input = vec![0xaa; 32];
            assert_eq!(seen.entered, Some((true, input.clone())), "inspected={inspected}");
            assert_eq!(seen.before, Some((true, input.clone())), "inspected={inspected}");
            assert_eq!(
                seen.returned.as_ref().map(|b| &b[..]),
                Some(&input[..]),
                "inspected={inspected}"
            );
            let kept = seen.kept.as_ref().and_then(MessageInput::as_owned);
            assert_eq!(kept.map(|b| &b[..]), Some(&input[..]), "inspected={inspected}");
        }
    }
}

/// [`MessageHooks::enter`] can run a message of its own before the entered one, and that message's
/// inspector hooks get the suspended caller, so they can change its memory and grow it into a new
/// allocation. The entered message's input is a range of that memory, so it reads what they left.
mod nested_enter {
    use super::*;
    use evm2::interpreter::Interpreter;

    struct Types;
    impl EvmTypesHost for Types {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = Vec<Bytes>;
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = ();
        type Host<'a> = Evm<'a, Self>;
        type MessageHooks = Nester;
    }

    const NESTED: Address = Address::with_last_byte(0x0e);

    /// Runs a message to [`NESTED`] on entering a call to [`CODE`], and keeps the call's input as
    /// it exits.
    struct Nester;
    impl MessageHooks<Types> for Nester {
        const RUNS_BEFORE: bool = false;

        fn enter(evm: &mut Evm<'_, Types>, m: &Message<Types>) {
            if m.destination == CODE {
                let mut nested: Message<Types> = MessageExt {
                    kind: MessageKind::Call,
                    gas_limit: 100_000,
                    depth: m.depth,
                    destination: NESTED,
                    call_target: NESTED,
                    code_address: NESTED,
                    ..MessageExt::default()
                };
                Host::execute_message(evm, &mut nested).unwrap();
            }
        }

        fn exit(
            evm: &mut Evm<'_, Types>,
            m: &Message<Types>,
            _: &Result<MessageResult<Types>, evm2::ExecutionError>,
        ) {
            if m.destination == CODE {
                let input = Bytes::copy_from_slice(evm.message_input(m));
                evm.ext_mut().push(input);
            }
        }
    }

    /// On the call to [`NESTED`], overwrites the suspended caller's memory and grows it past its
    /// capacity.
    struct Grower;
    impl evm2::Inspector<Types> for Grower {
        fn call(
            &mut self,
            interp: &mut Interpreter<'_, '_, Types>,
            m: &mut Message<Types>,
        ) -> Option<MessageResult<Types>> {
            if m.destination == NESTED {
                let memory = interp.memory_mut();
                memory.set(0, &[0xbb; 32]);
                assert!(memory.resize(0, 1 << 16).is_ok());
            }
            None
        }
    }

    #[test]
    fn entered_input_reads_what_a_nested_inspector_leaves_in_the_moved_caller_memory() {
        // MSTORE8(0, 0xaa); CALL(gas, CODE, 0, 0, 32, 0, 0): memory 0..32 is the input. Shorter
        // than 16 bytes, so the jump analysis takes its scalar path, which Miri can run.
        let mut parent = vec![op::PUSH1, 0xaa, op::PUSH0, op::MSTORE8];
        parent.extend([op::PUSH0, op::PUSH0, op::PUSH1, 32, op::PUSH0, op::PUSH0]);
        parent.extend([op::PUSH1, CODE[19], op::GAS, op::CALL]);
        // `CODE` has no code: the input is read before the call reaches the account.
        let mut evm = Evm::<Types>::new_with_ext(
            SpecId::PRAGUE,
            BlockEnv::<Types>::default(),
            TxRegistry::new(),
            InMemoryDB::default(),
            Precompiles::base(SpecId::PRAGUE),
            Vec::new(),
        );
        evm.set_inspector(Grower);
        let mut message: Message<Types> = MessageExt {
            kind: MessageKind::Call,
            gas_limit: 1_000_000,
            destination: PARENT,
            call_target: PARENT,
            code: Bytecode::new_legacy(Bytes::from(parent)),
            code_address: PARENT,
            ..MessageExt::default()
        };
        let result = Host::execute_message(&mut evm, &mut message).unwrap();
        assert_eq!(result.stop, InstrStop::Stop);
        assert_eq!(evm.ext().as_slice(), [Bytes::from_static(&[0xbb; 32])]);
    }
}
