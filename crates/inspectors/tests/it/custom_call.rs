//! A child frame shows in the step traces after the step that started it, whatever its opcode: a
//! type family can install an instruction that runs a message at an opcode that is neither a call
//! nor a create.

use alloy_consensus::{TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, Bytes, TxKind, hex};
use alloy_rpc_types_trace::{geth::DefaultFrame, parity::VmTrace};
use evm2::{
    BaseEvmTypes, Evm, Precompiles, SpecId,
    bytecode::Bytecode,
    ethereum::{TxEnvelope, ethereum_tx_registry},
    evm::{
        AccountInfo, InMemoryDB,
        config::{BaseEvmConfig, EvmConfig, ExecutionConfig},
    },
    interpreter::{instructions as instr, op},
    version::OpcodeConfig,
};
use evm2_inspectors::tracing::{TracingInspector, TracingInspectorConfig};

/// An opcode that no base version defines.
const CUSTOM_CALL: u8 = 0x0c;
const CALLER: Address = Address::repeat_byte(0xaa);
const TARGET: Address = Address::with_last_byte(0x42);
const CHILD: Address = Address::with_last_byte(0x43);

/// Osaka with `CALL`'s instruction, at `CALL`'s static gas, installed at [`CUSTOM_CALL`].
struct CustomCallConfig;

impl EvmConfig<BaseEvmTypes> for CustomCallConfig {
    const BASE_SPEC_ID: SpecId = SpecId::OSAKA;
    const OPCODE_CONFIG: &'static OpcodeConfig<BaseEvmTypes> = &{
        let mut config =
            OpcodeConfig::<BaseEvmTypes>::base::<BaseEvmConfig<{ SpecId::OSAKA as u32 }>>();
        config.set_instruction::<instr::call<BaseEvmTypes>>(CUSTOM_CALL, 100);
        config
    };
}

/// The geth struct logs and the Parity VM trace of a call to [`TARGET`], which calls [`CHILD`]
/// with `call_op`.
fn traces(call_op: u8) -> (DefaultFrame, VmTrace) {
    // CALL(GAS, CHILD, 0, 0, 0, 0, 0), POP, STOP; the child adds two numbers.
    let mut code = hex!("5f5f5f5f5f60435a").to_vec();
    code.extend([call_op, op::POP, op::STOP]);
    let child = hex!("600160020150").to_vec();
    let run = |config| {
        let mut db = InMemoryDB::default();
        for (address, code) in [(TARGET, &code), (CHILD, &child)] {
            db.insert_account_info(
                &address,
                AccountInfo::default().with_code(Bytecode::new_raw(Bytes::copy_from_slice(code))),
            );
        }
        let mut inspector = TracingInspector::new(config);
        let mut evm = Evm::<BaseEvmTypes>::new_with_execution_config(
            ExecutionConfig::for_config::<CustomCallConfig>(),
            SpecId::OSAKA,
            Default::default(),
            ethereum_tx_registry(SpecId::OSAKA),
            db,
            Precompiles::base(SpecId::OSAKA),
        );
        evm.set_inspector(&mut inspector);
        let tx = TxEnvelope::Legacy(TxLegacy {
            gas_limit: 100_000,
            to: TxKind::Call(TARGET),
            ..Default::default()
        });
        let res = evm.transact(&Recovered::new_unchecked(tx, CALLER)).unwrap().detach();
        assert!(res.result.is_success(), "{res:#?}");
        drop(evm);
        inspector
    };
    let geth = run(TracingInspectorConfig::default_geth()).geth_builder().geth_traces(
        0,
        Bytes::new(),
        Default::default(),
    );
    let vm_trace = run(TracingInspectorConfig::parity_vm_trace()).into_parity_builder().vm_trace();
    (geth, vm_trace)
}

#[test]
fn a_child_started_by_any_opcode_shows_after_its_step() {
    let (call_logs, call_vm) = traces(op::CALL);
    let (custom_logs, custom_vm) = traces(CUSTOM_CALL);
    // The eighth step, at pc 8, starts the child.
    let (at, pc) = (7, 8);

    // The struct logs: the child's steps follow the step that started it, at depth 2, as they
    // follow a `CALL`; nothing else differs but the opcode's name.
    let depths = |frame: &DefaultFrame| {
        frame.struct_logs.iter().map(|log| (log.pc, log.depth)).collect::<Vec<_>>()
    };
    assert_eq!(depths(&custom_logs), depths(&call_logs));
    assert_eq!(
        depths(&custom_logs)[at..at + 7],
        [(pc, 1), (0, 2), (2, 2), (4, 2), (5, 2), (6, 2), (pc + 1, 1)]
    );
    for (custom, call) in custom_logs.struct_logs.iter().zip(&call_logs.struct_logs) {
        if custom.pc == pc && custom.depth == 1 {
            assert_eq!((custom.op.as_ref(), call.op.as_ref()), ("opcode 0xc not defined", "CALL"));
        } else {
            assert_eq!(custom, call);
        }
    }

    // The VM trace: the step that started the child has the child's trace as its sub, as a
    // `CALL` has; no other step has one.
    assert_eq!(custom_vm.ops.len(), call_vm.ops.len());
    for (index, (custom, call)) in custom_vm.ops.iter().zip(&call_vm.ops).enumerate() {
        assert_eq!(custom.sub, call.sub, "op {index}");
        assert_eq!(custom.sub.is_some(), index == at, "op {index}");
        let (custom_ex, call_ex) = (custom.ex.as_ref().unwrap(), call.ex.as_ref().unwrap());
        assert_eq!((custom.pc, custom.cost, custom_ex.used), (call.pc, call.cost, call_ex.used));
        assert_eq!((&custom_ex.mem, &custom_ex.store), (&call_ex.mem, &call_ex.store));
        // The words a step pushes come from its opcode's stack outputs, which an undefined opcode
        // does not have.
        if index == at {
            assert_eq!((custom_ex.push.len(), call_ex.push.len()), (0, 1));
        } else {
            assert_eq!(custom_ex.push, call_ex.push, "op {index}");
        }
    }
    // The child's four instructions: the `STOP` past the end of its code is no VM-trace op.
    assert_eq!(custom_vm.ops[at].pc, pc as usize);
    assert_eq!(custom_vm.ops[at].sub.as_ref().unwrap().ops.len(), 4);
}
