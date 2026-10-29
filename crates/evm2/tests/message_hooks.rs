//! `MessageHooks` run for every message, on the plain and the inspected path alike, and can stop
//! a start or take back a success answer before evm2 commits it.

use alloy_primitives::{Address, Bytes, U256};
use evm2::{
    BaseEvmConfigSelector, Evm, EvmTypesHost, MessageHooks, NoopInspector, SpecId,
    bytecode::Bytecode,
    env::{BlockEnv, TxEnvExt},
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
        _: &mut GasTracker,
    ) -> Result<(), evm2::ExecutionError> {
        evm.ext_mut().push(format!("before_commit {} {stop:?}", m.call_target));
        if m.call_target == IDENTITY && stop.is_success() {
            *stop = InstrStop::Revert;
            *out = Bytes::from_static(b"taken back");
        }
        Ok(())
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
    let result = Host::execute_message(&mut evm, &TxEnvExt::default(), &mut message).unwrap();
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
    Host::execute_message(&mut evm, &TxEnvExt::default(), &mut message).unwrap();
    assert_eq!(
        evm.ext(),
        &[format!("enter {}", Address::ZERO), format!("exit {} true", Address::ZERO),]
    );
}

#[test]
fn hook_errors_roll_back_state_and_pair_observers() {
    let mut evm = evm();
    let target = Address::with_last_byte(0xfe);
    let mut message = Message::<Types> { call_target: target, ..Default::default() };
    let result = Host::execute_message(&mut evm, &TxEnvExt::default(), &mut message);
    assert!(matches!(result, Err(evm2::ExecutionError::Fatal(_))));
    assert_eq!(evm.state_mut().account(&PARENT).unwrap().get().unwrap().nonce, 0);
    assert_eq!(
        evm.ext(),
        &[format!("enter {target}"), format!("before {target}"), format!("exit {target} false"),]
    );
}
