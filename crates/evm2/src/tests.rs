use crate::{
    BaseEvmTypes, Evm, EvmFeatures, ExecutionConfig, Inspector, Precompiles, SpecId, Version,
    bytecode::Bytecode,
    env::BlockEnvExt,
    ethereum::{
        LazyTxEip7702, RecoveredTxEnvelope, TxEnvelope,
        eip7702::{AuthRefunds, Eip7702Authorization, RuntimeAuthCharges, apply_auth_list},
        ethereum_tx_registry, prepare_initial_frame,
    },
    evm::{AccountInfo, InMemoryDB, SYSTEM_ADDRESS},
    interpreter::{GasTracker, Host, InstrStop, MessageExt, Word, op},
    registry::TxRegistry,
    test_utils::{legacy_bytecode, push, push_address, push_all, return_top_word},
    version::GasId,
};
use alloc::{vec, vec::Vec};
use alloy_consensus::{TxEip1559, TxEip2930, TxEip7702, TxLegacy, transaction::Recovered};
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::{Address, Log, TxKind, U256, bytes, hex};

type TestEvm = Evm<'static, BaseEvmTypes>;

fn run_tx(evm: &mut TestEvm, destination: Address, code: impl Into<Vec<u8>>) {
    let mut message = MessageExt {
        destination,
        code_address: destination,
        gas_limit: 100_000,
        code: legacy_bytecode(code),
        ..Default::default()
    };
    let result = Host::execute_message(evm, &mut message).unwrap();
    assert!(result.is_success());
}

#[test]
fn evm_executes_storage_transaction() {
    let contract = Address::repeat_byte(0x11);
    let mut evm = TestEvm::new(
        SpecId::OSAKA,
        BlockEnvExt::default(),
        TxRegistry::new(),
        InMemoryDB::default(),
        Precompiles::base(SpecId::OSAKA),
    );

    assert!(evm.database_as::<InMemoryDB>().is_some());
    assert!(evm.database_as_mut::<InMemoryDB>().is_some());
    assert!(evm.precompiles_as::<Precompiles>().is_some());
    assert!(evm.precompiles_as_mut::<Precompiles>().is_some());
    evm.set_database(InMemoryDB::default());
    evm.set_precompiles(Precompiles::base(SpecId::OSAKA));

    run_tx(&mut evm, contract, [op::PUSH1, 0x2a, op::PUSH1, 0x01, op::SSTORE, op::STOP]);

    assert_eq!(evm.state.storage_slot(&contract, Word::ONE).unwrap().current(), Word::from(0x2a));
}

#[test]
fn evm_runs_transactions_against_initial_state() {
    let contract = Address::repeat_byte(0x22);
    let mut database = InMemoryDB::default();
    database.insert_account_info(&contract, AccountInfo { nonce: 1, ..Default::default() });
    database.insert_account_storage(&contract, &Word::ONE, &Word::from(40));
    let mut evm = TestEvm::new(
        SpecId::OSAKA,
        BlockEnvExt::default(),
        TxRegistry::new(),
        database,
        Precompiles::base(SpecId::OSAKA),
    );

    run_tx(
        &mut evm,
        contract,
        [
            op::PUSH1,
            0x01,
            op::SLOAD,
            op::PUSH1,
            0x02,
            op::ADD,
            op::PUSH1,
            0x02,
            op::SSTORE,
            op::STOP,
        ],
    );
    run_tx(&mut evm, contract, [op::PUSH1, 0x07, op::PUSH1, 0x01, op::SSTORE, op::STOP]);

    assert_eq!(evm.state.storage_slot(&contract, Word::ONE).unwrap().current(), Word::from(7));
    assert_eq!(evm.state.storage_slot(&contract, Word::from(2)).unwrap().current(), Word::from(42));
}

#[test]
fn evm_propagates_child_sstore_negative_refund() {
    let contract = Address::with_last_byte(0x44);
    let mut child_code = Vec::new();
    push(&mut child_code, 7);
    push(&mut child_code, 0);
    child_code.extend([op::SSTORE, op::STOP]);

    let mut database = InMemoryDB::default();
    database.insert_account_info(
        &contract,
        AccountInfo { nonce: 1, code: Some(legacy_bytecode(child_code)), ..Default::default() },
    );
    database.insert_account_storage(&contract, &Word::ZERO, &Word::from(5));
    let mut evm = TestEvm::new(
        SpecId::LONDON,
        BlockEnvExt::default(),
        TxRegistry::new(),
        database,
        Precompiles::base(SpecId::LONDON),
    );

    let mut parent_code = Vec::new();
    push(&mut parent_code, 0);
    push(&mut parent_code, 0);
    parent_code.push(op::SSTORE);
    push(&mut parent_code, 0); // return length
    push(&mut parent_code, 0); // return offset
    push(&mut parent_code, 0); // input length
    push(&mut parent_code, 0); // input offset
    push(&mut parent_code, 0); // value
    push(&mut parent_code, 0x44); // callee
    push(&mut parent_code, 50_000); // gas
    parent_code.extend([op::CALL, op::STOP]);

    let mut message = MessageExt {
        destination: contract,
        code_address: contract,
        gas_limit: 100_000,
        code: legacy_bytecode(parent_code),
        ..Default::default()
    };
    let result = Host::execute_message(&mut evm, &mut message).unwrap();

    assert!(result.is_success());
    assert_eq!(result.gas.refunded(), 0);
}

#[test]
fn evm_reports_invalid_transaction_execution() {
    let contract = Address::repeat_byte(0x33);
    let mut evm = TestEvm::new(
        SpecId::OSAKA,
        BlockEnvExt::default(),
        TxRegistry::new(),
        InMemoryDB::default(),
        Precompiles::base(SpecId::OSAKA),
    );
    let mut message = MessageExt {
        destination: contract,
        code_address: contract,
        gas_limit: 100_000,
        code: legacy_bytecode([op::PUSH1, 0x01, op::SSTORE]),
        ..Default::default()
    };
    let result = Host::execute_message(&mut evm, &mut message).unwrap();

    assert_eq!(result.stop, InstrStop::StackUnderflow);
}

#[test]
fn eip8037_sibling_refill_restores_parent_gas_left() {
    let parent = Address::repeat_byte(0x11);
    let setter = Address::repeat_byte(0xa1);
    let clearer = Address::repeat_byte(0xb2);
    let caller = Address::repeat_byte(0xcc);
    let mut parent_code = Vec::new();
    for target in [setter, clearer] {
        // DELEGATECALL(gas, target, 0, 0, 0, 0).
        for _ in 0..4 {
            parent_code.extend([op::PUSH1, 0]);
        }
        parent_code.push(op::PUSH20);
        parent_code.extend_from_slice(target.as_slice());
        parent_code.extend([op::GAS, op::DELEGATECALL, op::POP]);
    }
    // Return the gas visible to the parent after both siblings finish.
    parent_code.extend([
        op::GAS,
        op::PUSH1,
        0,
        op::MSTORE,
        op::PUSH1,
        32,
        op::PUSH1,
        0,
        op::RETURN,
    ]);

    let mut database = InMemoryDB::default();
    for (address, code) in [
        (parent, legacy_bytecode(parent_code)),
        (setter, legacy_bytecode([op::PUSH1, 1, op::PUSH1, 0, op::SSTORE, op::STOP])),
        (clearer, legacy_bytecode([op::PUSH1, 0, op::PUSH1, 0, op::SSTORE, op::STOP])),
    ] {
        database
            .insert_account_info(&address, AccountInfo::default().with_nonce(1).with_code(code));
    }
    database.insert_account_info(
        &caller,
        AccountInfo { balance: U256::from(u64::MAX), ..Default::default() },
    );
    let tx = Recovered::new_unchecked(
        TxEnvelope::Legacy(TxLegacy {
            gas_limit: 1_000_000,
            to: TxKind::Call(parent),
            ..Default::default()
        }),
        caller,
    );
    let run = |enabled| {
        let mut version = Version::new(SpecId::AMSTERDAM);
        version.features.remove(EvmFeatures::EIP2780);
        version.features.set(EvmFeatures::EIP8037, enabled);
        version.gas_params.set(GasId::SstoreSetState, 200_000);
        let mut evm = TestEvm::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(SpecId::AMSTERDAM, version),
            SpecId::AMSTERDAM,
            BlockEnvExt::default(),
            ethereum_tx_registry(SpecId::AMSTERDAM),
            database.clone(),
            Precompiles::base(SpecId::AMSTERDAM),
        );
        evm.transact(&tx).unwrap().discard()
    };

    let baseline = run(false);
    let result = run(true);
    assert!(baseline.is_success());
    assert!(result.is_success());
    assert_eq!(result.state_gas_spent(), 0);
    assert_eq!(result.output.len(), 32);
    assert_eq!(result.output, baseline.output);
}

#[test]
fn eip2780_authorization_charges_no_state_gas_without_eip8037() {
    let caller = Address::repeat_byte(0xbb);
    let recipient = Address::repeat_byte(0xaa);
    let authority = Address::repeat_byte(0xcc);
    let delegate = Address::repeat_byte(0xdd);

    let mut database = InMemoryDB::default();
    database.insert_account_info(
        &caller,
        AccountInfo { balance: U256::from(u64::MAX), ..Default::default() },
    );
    let mut version = Version::new(SpecId::AMSTERDAM);
    version.features.remove(EvmFeatures::EIP8037);
    let chain_id = version.chain_id;
    let mut evm = TestEvm::new_with_execution_config(
        ExecutionConfig::for_spec_and_version(SpecId::AMSTERDAM, version),
        SpecId::AMSTERDAM,
        BlockEnvExt::default(),
        ethereum_tx_registry(SpecId::AMSTERDAM),
        database,
        Precompiles::base(SpecId::AMSTERDAM),
    );
    // TX_BASE + cold recipient + per-authorization base + the authority's ACCOUNT_WRITE.
    let gas_limit = 12_000 + 3_000 + 7_816 + 9_000;
    let tx = Recovered::new_unchecked(
        TxEnvelope::Eip7702(LazyTxEip7702::from_cached_recovered_authorizations(
            TxEip7702 {
                chain_id,
                to: recipient,
                gas_limit,
                authorization_list: vec![unsigned(Authorization {
                    chain_id: U256::ZERO,
                    address: delegate,
                    nonce: 0,
                })],
                ..Default::default()
            },
            vec![Some(authority)],
        )),
        caller,
    );

    let result = evm.transact(&tx).unwrap().detach();
    assert!(result.result.is_success());
    assert_eq!(result.result.state_gas_spent(), 0);
    let authority = result.pending_state.account_info(&authority).unwrap();
    assert_eq!(authority.nonce, 1);
    assert_eq!(authority.code_hash, Bytecode::new_eip7702(delegate).hash_slow());
}

/// Wraps an authorization with a placeholder signature, for use with a cached authority.
fn unsigned(authorization: Authorization) -> SignedAuthorization {
    SignedAuthorization::new_unchecked(authorization, 0, U256::ZERO, U256::ZERO)
}

fn absent_authority_evm(spec: SpecId, touched: Address) -> TestEvm {
    let mut evm = TestEvm::new(
        spec,
        BlockEnvExt::default(),
        ethereum_tx_registry(spec),
        InMemoryDB::default(),
        Precompiles::base(spec),
    );
    evm.state.account(&touched).unwrap().touch();
    evm
}

fn auth_for(authority: Address) -> CustomAuthorization {
    CustomAuthorization {
        nonce: 0,
        address: Address::with_last_byte(0xdd),
        authority: Some(authority),
    }
}

#[test]
fn apply_auth_list_refunds_touched_absent_authority() {
    let touched = Address::with_last_byte(0xa1);
    let untouched = Address::with_last_byte(0xa2);
    let mut evm = absent_authority_evm(SpecId::PRAGUE, touched);
    let mut refunds = AuthRefunds::new(evm.version());

    apply_auth_list(&mut evm, 1, [auth_for(touched), auth_for(untouched)], &mut refunds).unwrap();

    // An authority is refunded unless it is absent and untouched.
    let per_auth = evm.version().gas_params.get(GasId::TxEip7702AuthRefund);
    assert_eq!(refunds.execution_refund, per_auth);
}

#[rstest::rstest]
#[case::legacy(0)]
#[case::eip2930(1)]
#[case::eip1559(2)]
fn top_level_create_uses_sender_state_nonce(
    #[case] tx_type: u8,
    #[values(false, true)] occupied_first_address: bool,
    #[values((false, 0), (false, 9), (true, 5))] nonce_check_and_tx_nonce: (bool, u64),
) {
    let (nonce_check, nonce) = nonce_check_and_tx_nonce;
    let caller = Address::from([0xbb; 20]);
    let destination = caller.create(5);
    let first_address = caller.create(0);
    let code = legacy_bytecode([op::STOP]);
    let mut database = InMemoryDB::default();
    database.insert_account_info(
        &caller,
        AccountInfo { nonce: 5, balance: U256::from(u64::MAX), ..Default::default() },
    );
    if occupied_first_address {
        database.insert_account_info(
            &first_address,
            AccountInfo::default().with_nonce(1).with_code(code.clone()),
        );
    }
    let mut version = Version::new(SpecId::OSAKA);
    version.features.set(EvmFeatures::NONCE_CHECK, nonce_check);
    let chain_id = version.chain_id;
    let mut evm = TestEvm::new_with_execution_config(
        ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
        SpecId::OSAKA,
        BlockEnvExt::default(),
        ethereum_tx_registry(SpecId::OSAKA),
        database,
        Precompiles::base(SpecId::OSAKA),
    );
    // Return one zero byte as deployed STOP code.
    let input = [op::PUSH1, 1, op::PUSH1, 0, op::RETURN].into();
    let gas_limit = 100_000;
    let value = U256::from(7);
    let tx = match tx_type {
        0 => TxEnvelope::Legacy(TxLegacy {
            nonce,
            gas_limit,
            value,
            input,
            to: TxKind::Create,
            ..Default::default()
        }),
        1 => TxEnvelope::Eip2930(TxEip2930 {
            chain_id,
            nonce,
            gas_limit,
            value,
            input,
            to: TxKind::Create,
            ..Default::default()
        }),
        2 => TxEnvelope::Eip1559(TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            value,
            input,
            to: TxKind::Create,
            ..Default::default()
        }),
        _ => unreachable!(),
    };
    let result = evm.transact(&Recovered::new_unchecked(tx, caller)).unwrap().commit();
    assert!(result.status, "{result:?}");
    assert_eq!(result.created_address, Some(destination));
    let created = evm.state.account_info_untracked(&destination).unwrap().unwrap();
    assert_eq!(created.nonce, 1);
    assert_eq!(created.balance, value);
    assert_eq!(created.code_hash, code.hash_slow());
    assert_eq!(evm.state.account(&caller).unwrap().nonce(), 6);
    let first = evm.state.account(&first_address).unwrap();
    if occupied_first_address {
        assert_eq!(first.nonce(), 1);
        assert_eq!(first.code_hash(), code.hash_slow());
        assert_eq!(first.balance(), U256::ZERO);
    } else {
        assert!(first.get().is_none());
    }
}

#[test]
fn eip2780_touched_absent_authority_pays_no_new_account_state_gas() {
    let authority = Address::with_last_byte(0xa1);
    let state_gas_spent = |touched: Address| {
        let mut evm = absent_authority_evm(SpecId::AMSTERDAM, touched);
        let mut gas = GasTracker::new_with_execution_gas_and_reservoir(1_000_000, 1_000_000);
        let mut charges = RuntimeAuthCharges::new(
            evm.version(),
            &mut gas,
            Address::with_last_byte(0xb0),
            Address::with_last_byte(0xc0),
            U256::ZERO,
        );
        assert!(!apply_auth_list(&mut evm, 1, [auth_for(authority)], &mut charges).unwrap());
        (gas.state_gas_spent(), evm.version().gas_params.new_account_state_gas())
    };

    let (untouched, new_account) = state_gas_spent(Address::with_last_byte(0xff));
    let (touched, _) = state_gas_spent(authority);
    assert_eq!(untouched - touched, i64::try_from(new_account).unwrap());
}

const LOG_CALLER: Address = Address::with_last_byte(0xa0);
const LOG_CONTRACT: Address = Address::with_last_byte(0xa1);
const LOG_EMITTER: Address = Address::with_last_byte(0xa2);

/// Builds an Amsterdam EVM where `LOG_CONTRACT` runs `code` and `LOG_EMITTER` emits one `LOG0`.
fn log_collection_evm(log_collection: bool, code: Vec<u8>) -> TestEvm {
    let mut database = InMemoryDB::default();
    database.insert_account_info(
        &LOG_CALLER,
        AccountInfo { balance: U256::from(u64::MAX), ..Default::default() },
    );
    for (address, code) in
        [(LOG_CONTRACT, code), (LOG_EMITTER, vec![op::PUSH0, op::PUSH0, op::LOG0])]
    {
        database.insert_account_info(
            &address,
            AccountInfo::default().with_nonce(1).with_code(legacy_bytecode(code)),
        );
    }
    let mut version = Version::new(SpecId::AMSTERDAM);
    version.features.set(EvmFeatures::LOG_COLLECTION, log_collection);
    TestEvm::new_with_execution_config(
        ExecutionConfig::for_spec_and_version(SpecId::AMSTERDAM, version),
        SpecId::AMSTERDAM,
        BlockEnvExt::default(),
        ethereum_tx_registry(SpecId::AMSTERDAM),
        database,
        Precompiles::base(SpecId::AMSTERDAM),
    )
}

/// Calls `LOG_CONTRACT` with value, so EIP-7708 adds a transfer log.
fn log_collection_tx() -> RecoveredTxEnvelope {
    Recovered::new_unchecked(
        TxEnvelope::Legacy(TxLegacy {
            gas_limit: 1_000_000,
            to: TxKind::Call(LOG_CONTRACT),
            value: U256::from(7),
            ..Default::default()
        }),
        LOG_CALLER,
    )
}

#[test]
fn log_collection_off_keeps_log_semantics() {
    // LOG4 over memory that is already allocated, then LOG0 past it, which grows memory to four
    // words. Returns MSIZE.
    let mut logs = Vec::new();
    push_all(&mut logs, [0xbeef, 0]);
    logs.push(op::MSTORE);
    push_all(&mut logs, [4, 3, 2, 1, 2, 30]);
    logs.push(op::LOG4);
    push_all(&mut logs, [33, 64]);
    logs.extend([op::LOG0, op::MSIZE]);
    return_top_word(&mut logs);

    let mut memory_oog = Vec::new();
    push_all(&mut memory_oog, [Word::ONE, Word::MAX]);
    memory_oog.push(op::LOG0);

    let mut underflow = Vec::new();
    push_all(&mut underflow, [0, 0]);
    underflow.push(op::LOG2);

    // A static call into a logging contract fails; the call's success flag is returned.
    let mut static_call = Vec::new();
    push_all(&mut static_call, [0, 0, 0, 0]);
    push_address(&mut static_call, &LOG_EMITTER);
    static_call.extend([op::GAS, op::STATICCALL]);
    return_top_word(&mut static_call);

    for (name, code, status, output, logs) in [
        ("logs", logs, true, Some(Word::from(128)), 3),
        ("memory_oog", memory_oog, false, None, 0),
        ("underflow", underflow, false, None, 0),
        ("static_call", static_call, true, Some(Word::ZERO), 1),
    ] {
        let run = |log_collection| {
            log_collection_evm(log_collection, code.clone())
                .transact(&log_collection_tx())
                .unwrap()
                .discard()
        };
        let mut on = run(true);
        let off = run(false);

        assert_eq!(on.is_success(), status, "{name}");
        if let Some(output) = output {
            assert_eq!(on.output[..], output.to_be_bytes::<32>(), "{name}");
        }
        assert_eq!(on.logs.len(), logs, "{name}");
        assert!(off.logs.is_empty(), "{name}");
        on.logs.clear();
        assert_eq!(on, off, "{name}");
    }
}

#[test]
fn log_collection_off_still_inspects_logs() {
    #[derive(Default)]
    struct LogInspector(Vec<Log>);

    impl Inspector<BaseEvmTypes> for LogInspector {
        fn log(&mut self, log: &Log, _host: &mut Evm<'_, BaseEvmTypes>) {
            self.0.push(log.clone());
        }
    }

    let code = vec![op::PUSH0, op::PUSH0, op::LOG0];
    let collected =
        log_collection_evm(true, code.clone()).transact(&log_collection_tx()).unwrap().discard();
    let mut evm = log_collection_evm(false, code);
    evm.set_inspector(LogInspector::default());
    let inspected = evm.transact(&log_collection_tx()).unwrap().discard();
    let inspector = evm.clear_inspector_as::<LogInspector>().unwrap();

    assert!(inspected.is_success());
    assert!(inspected.logs.is_empty());
    assert_eq!(
        inspector.0.iter().map(|log| log.address).collect::<Vec<_>>(),
        [SYSTEM_ADDRESS, LOG_CONTRACT]
    );
    assert_eq!(inspector.0, collected.logs);
}

#[rstest::rstest]
#[case::empty_precompile(2, Bytecode::default(), &SHA256_FOUR_BYTES, 72, 230)]
#[case::precompile_with_code(2, legacy_bytecode([op::STOP]), &SHA256_FOUR_BYTES, 72, 230)]
#[case::precompile_with_delegation(
    2, Bytecode::new_eip7702(Address::with_last_byte(0x33)), &SHA256_FOUR_BYTES, 72, 2830
)]
#[case::precompile_with_self_delegation(
    2, Bytecode::new_eip7702(Address::with_last_byte(2)), &SHA256_FOUR_BYTES, 72, 330
)]
#[case::ordinary_delegation(
    0x55, Bytecode::new_eip7702(Address::with_last_byte(0x33)),
    &hex!("000000000000000000000000000000000000000000000000000000000000002a"), 18, 5276
)]
#[case::delegation_to_precompile(
    0x55, Bytecode::new_eip7702(Address::with_last_byte(2)), &[], 0, 2755
)]
fn precompile_dispatch_uses_original_callee(
    #[case] callee: u8,
    #[case] code: Bytecode,
    #[case] expected_output: &[u8],
    #[case] root_gas: u64,
    #[case] call_gas: u64,
    #[values(
        None,
        Some(op::CALL),
        Some(op::CALLCODE),
        Some(op::DELEGATECALL),
        Some(op::STATICCALL)
    )]
    opcode: Option<u8>,
) {
    let callee = Address::with_last_byte(callee);
    let delegate = Address::with_last_byte(0x33);
    let parent = Address::with_last_byte(0x44);
    let caller = Address::with_last_byte(0xaa);
    let mut database = InMemoryDB::default();
    database.insert_account_info(&callee, AccountInfo::default().with_code(code));
    database.insert_account_info(
        &delegate,
        AccountInfo::default().with_code(legacy_bytecode(hex!("602a60005260206000f3"))),
    );

    let target = if let Some(opcode) = opcode {
        // Copy transaction input into memory, call the callee, and return its entire output.
        let mut code = vec![op::CALLDATASIZE];
        push_all(&mut code, [0, 0]);
        code.push(op::CALLDATACOPY);
        push_all(&mut code, [0, 0, 4, 0]);
        if matches!(opcode, op::CALL | op::CALLCODE) {
            push(&mut code, 0);
        }
        push_address(&mut code, &callee);
        code.extend([op::GAS, opcode, op::POP, op::RETURNDATASIZE]);
        push_all(&mut code, [0, 0]);
        code.extend([op::RETURNDATACOPY, op::RETURNDATASIZE]);
        push(&mut code, 0);
        code.push(op::RETURN);
        database
            .insert_account_info(&parent, AccountInfo::default().with_code(legacy_bytecode(code)));
        parent
    } else {
        callee
    };
    let mut evm = TestEvm::new(
        SpecId::PRAGUE,
        BlockEnvExt::default(),
        TxRegistry::new(),
        database,
        Precompiles::base(SpecId::PRAGUE),
    );
    evm.warm_precompiles();
    evm.state.prewarm(&caller);
    evm.state.prewarm(&target);
    let mut gas = GasTracker::new(100_000);
    let mut frame = prepare_initial_frame(
        &mut evm,
        caller,
        0,
        TxKind::Call(target),
        &bytes!("01020304"),
        U256::ZERO,
        &mut gas,
    )
    .unwrap();
    let result = Host::execute_message(&mut evm, &mut frame.message).unwrap();

    assert!(result.is_success(), "{:?}", result.stop);
    assert_eq!(result.output.as_ref(), expected_output);
    // Geth's Prague gas usage includes delegation resolution even for precompile callees.
    let expected_gas = match opcode {
        None => root_gas,
        Some(op::DELEGATECALL | op::STATICCALL) => call_gas - 3,
        Some(_) => call_gas,
    };
    assert_eq!(result.gas.spent(), expected_gas);
}

// SHA-256 of the four input bytes 0x01020304.
const SHA256_FOUR_BYTES: [u8; 32] =
    hex!("9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a");

/// Authorization type that is not [`crate::ethereum::LazyAuthorization`].
struct CustomAuthorization {
    nonce: u64,
    address: Address,
    authority: Option<Address>,
}

impl Eip7702Authorization for CustomAuthorization {
    fn chain_id(&self) -> U256 {
        U256::ZERO
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn address(&self) -> Address {
        self.address
    }

    fn authority(&self) -> Option<Address> {
        self.authority
    }
}

#[test]
fn apply_auth_list_accepts_custom_filtered_authorizations() {
    let applied = Address::with_last_byte(0xa1);
    let skipped = Address::with_last_byte(0xa2);
    let delegate = Address::with_last_byte(0xdd);
    let auth = |authority, nonce| CustomAuthorization { nonce, address: delegate, authority };
    let list = [
        auth(Some(applied), 1),
        auth(Some(skipped), 1),
        // Unrecoverable authority and stale nonce are rejected.
        auth(None, 1),
        auth(Some(Address::with_last_byte(0xa3)), 5),
    ];
    let mut database = InMemoryDB::default();
    for address in [applied, skipped] {
        database.insert_account_info(&address, AccountInfo::default().with_nonce(1));
    }
    let mut evm = TestEvm::new(
        SpecId::PRAGUE,
        BlockEnvExt::default(),
        ethereum_tx_registry(SpecId::PRAGUE),
        database,
        Precompiles::base(SpecId::PRAGUE),
    );
    let mut refunds = AuthRefunds::new(evm.version());

    let oog = apply_auth_list(
        &mut evm,
        1,
        list.into_iter().filter(|auth| auth.authority != Some(skipped)),
        &mut refunds,
    )
    .unwrap();

    assert!(!oog);
    let delegation = Bytecode::new_eip7702(delegate).hash_slow();
    assert_eq!(evm.state.account(&applied).unwrap().code_hash(), delegation);
    assert_ne!(evm.state.account(&skipped).unwrap().code_hash(), delegation);
    // Before EIP-8037 only the existing, applied authority is refunded.
    let per_auth = evm.version().gas_params.get(GasId::TxEip7702AuthRefund);
    assert_eq!(refunds.execution_refund, per_auth);
}

mod before_initial_frame {
    use super::*;
    use crate::{
        TxResult,
        ethereum::{eip1559, eip2930, eip4844, eip7702, legacy, runtime_oog_result},
        evm::handler::{DefaultTxHandlerHooks, TxHandlerHooks},
        interpreter::MessageResult,
        registry::{HandlerResult, handler},
    };
    use alloy_consensus::{TxEip4844, TxEip4844Variant};
    use alloy_primitives::B256;
    use core::cell::Cell;

    const CALLER: Address = Address::with_last_byte(0xb1);
    const RECIPIENT: Address = Address::with_last_byte(0xb2);
    const AUTHORITY: Address = Address::with_last_byte(0xb3);
    const DELEGATE: Address = Address::with_last_byte(0xb4);
    const GAS_LIMIT: u64 = 1_000_000;
    const CHARGE: u64 = 40_000;

    std::thread_local! {
        static SEEN: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
    }

    fn registry<H: TxHandlerHooks<BaseEvmTypes> + 'static>()
    -> TxRegistry<BaseEvmTypes, TxResult<BaseEvmTypes>> {
        type T = BaseEvmTypes;
        TxRegistry::new()
            .with_handler(
                0,
                TxEnvelope::as_legacy,
                handler(legacy::prepare_with_hooks::<T, H>, legacy::execute_prepared::<T, H>),
            )
            .with_handler(
                1,
                TxEnvelope::as_eip2930,
                handler(eip2930::prepare_with_hooks::<T, H>, eip2930::execute_prepared::<T, H>),
            )
            .with_handler(
                2,
                TxEnvelope::as_eip1559,
                handler(eip1559::prepare_with_hooks::<T, H>, eip1559::execute_prepared::<T, H>),
            )
            .with_handler(
                3,
                TxEnvelope::as_eip4844,
                handler(eip4844::prepare_with_hooks::<T, H>, eip4844::execute_prepared::<T, H>),
            )
            .with_handler(
                4,
                TxEnvelope::as_eip7702,
                handler(eip7702::prepare_with_hooks::<T, H>, eip7702::execute_prepared::<T, H>),
            )
    }

    /// The recipient returns the gas its frame starts with (`GAS`) and stores 1 in slot 1, or
    /// reverts after reading it.
    fn evm<H: TxHandlerHooks<BaseEvmTypes> + 'static>(reverts: bool) -> TestEvm {
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &CALLER,
            AccountInfo { balance: U256::from(u64::MAX), ..Default::default() },
        );
        let mut code = vec![op::GAS, op::PUSH1, 1, op::PUSH1, 1, op::SSTORE];
        if reverts {
            code.extend([op::PUSH0, op::MSTORE, op::PUSH1, 32, op::PUSH0, op::REVERT]);
        } else {
            return_top_word(&mut code);
        }
        database.insert_account_info(
            &RECIPIENT,
            AccountInfo::default().with_nonce(1).with_code(legacy_bytecode(code)),
        );
        TestEvm::new(
            SpecId::AMSTERDAM,
            BlockEnvExt::default(),
            registry::<H>(),
            database,
            Precompiles::base(SpecId::AMSTERDAM),
        )
    }

    fn tx(tx_type: u8) -> RecoveredTxEnvelope {
        let chain_id = Version::new(SpecId::AMSTERDAM).chain_id;
        let to = TxKind::Call(RECIPIENT);
        let tx = match tx_type {
            0 => TxEnvelope::Legacy(TxLegacy { gas_limit: GAS_LIMIT, to, ..Default::default() }),
            1 => TxEnvelope::Eip2930(TxEip2930 {
                chain_id,
                gas_limit: GAS_LIMIT,
                to,
                ..Default::default()
            }),
            2 => TxEnvelope::Eip1559(TxEip1559 {
                chain_id,
                gas_limit: GAS_LIMIT,
                to,
                ..Default::default()
            }),
            3 => TxEnvelope::Eip4844(TxEip4844Variant::TxEip4844(TxEip4844 {
                chain_id,
                gas_limit: GAS_LIMIT,
                to: RECIPIENT,
                blob_versioned_hashes: vec![B256::with_last_byte(1).with_first_byte(1)],
                max_fee_per_blob_gas: 1,
                ..Default::default()
            })),
            4 => TxEnvelope::Eip7702(LazyTxEip7702::from_cached_recovered_authorizations(
                TxEip7702 {
                    chain_id,
                    gas_limit: GAS_LIMIT,
                    to: RECIPIENT,
                    authorization_list: vec![unsigned(Authorization {
                        chain_id: U256::ZERO,
                        address: DELEGATE,
                        nonce: 0,
                    })],
                    ..Default::default()
                },
                vec![Some(AUTHORITY)],
            )),
            _ => unreachable!(),
        };
        Recovered::new_unchecked(tx, CALLER)
    }

    trait WithFirstByte {
        fn with_first_byte(self, byte: u8) -> Self;
    }

    impl WithFirstByte for B256 {
        fn with_first_byte(mut self, byte: u8) -> Self {
            self.0[0] = byte;
            self
        }
    }

    /// Runs `tx_type` with hooks `H`: the result, the recipient's slot 1 and whether the
    /// authority was delegated.
    fn run<H: TxHandlerHooks<BaseEvmTypes> + 'static>(
        tx_type: u8,
        reverts: bool,
    ) -> (TxResult<BaseEvmTypes>, Word, bool) {
        let mut evm = evm::<H>(reverts);
        let result = evm.transact(&tx(tx_type)).unwrap().commit();
        let slot = evm.state.storage_slot(&RECIPIENT, Word::ONE).unwrap().current();
        let delegated = evm
            .state
            .account_info_untracked(&AUTHORITY)
            .unwrap()
            .is_some_and(|info| info.code_hash == Bytecode::new_eip7702(DELEGATE).hash_slow());
        (result, slot, delegated)
    }

    /// The frame's starting gas the recipient returned.
    fn frame_gas(result: &TxResult<BaseEvmTypes>) -> u64 {
        U256::from_be_slice(&result.output).to::<u64>()
    }

    /// Observes where the hook runs and then does what the default does.
    struct Observe;

    impl TxHandlerHooks<BaseEvmTypes> for Observe {
        fn before_initial_frame(
            host: &mut Evm<'_, BaseEvmTypes>,
            envelope: &TxEnvelope,
            tx_gas: &mut GasTracker,
        ) -> HandlerResult<Option<MessageResult<BaseEvmTypes>>> {
            // After the transaction environment and the pre-execution changes: the sender's nonce
            // is bumped, an EIP-7702 authority applied, the recipient not yet loaded for the frame.
            assert_eq!(Host::tx_env(host).origin, CALLER);
            assert_eq!(host.state.account_info_untracked(&CALLER).unwrap().unwrap().nonce, 1);
            if envelope.as_eip7702().is_some() {
                let authority = host.state.account_info_untracked(&AUTHORITY).unwrap().unwrap();
                assert_eq!(authority.code_hash, Bytecode::new_eip7702(DELEGATE).hash_slow());
            }
            SEEN.with(|seen| {
                assert!(seen.get().is_none(), "runs once per transaction");
                seen.set(Some((tx_gas.remaining(), tx_gas.reservoir())));
            });
            <DefaultTxHandlerHooks as TxHandlerHooks<BaseEvmTypes>>::before_initial_frame(
                host, envelope, tx_gas,
            )
        }
    }

    /// Charges `CHARGE` of state gas before the first frame.
    struct Charge;

    impl TxHandlerHooks<BaseEvmTypes> for Charge {
        fn before_initial_frame(
            _host: &mut Evm<'_, BaseEvmTypes>,
            _envelope: &TxEnvelope,
            tx_gas: &mut GasTracker,
        ) -> HandlerResult<Option<MessageResult<BaseEvmTypes>>> {
            tx_gas.spend_state(CHARGE).unwrap();
            Ok(None)
        }
    }

    /// Settles every transaction without a frame, as an included out-of-gas.
    struct Settle;

    impl TxHandlerHooks<BaseEvmTypes> for Settle {
        fn before_initial_frame(
            _host: &mut Evm<'_, BaseEvmTypes>,
            _envelope: &TxEnvelope,
            tx_gas: &mut GasTracker,
        ) -> HandlerResult<Option<MessageResult<BaseEvmTypes>>> {
            Ok(Some(runtime_oog_result(tx_gas.limit(), tx_gas.reservoir())))
        }
    }

    /// The default hook runs once, after the transaction environment and the pre-execution
    /// changes, immediately before the first frame, on the gas the first frame starts from, and
    /// changes nothing.
    #[rstest::rstest]
    fn default_runs_before_the_first_frame_and_changes_nothing(
        #[values(0, 1, 2, 3, 4)] tx_type: u8,
    ) {
        SEEN.with(|seen| seen.set(None));
        let (observed, slot, delegated) = run::<Observe>(tx_type, false);
        let (default, default_slot, default_delegated) =
            run::<DefaultTxHandlerHooks>(tx_type, false);
        assert!(default.status, "{default:?}");
        assert_eq!(observed, default);
        assert_eq!((slot, delegated), (default_slot, default_delegated));
        assert_eq!(slot, Word::ONE);
        assert_eq!(delegated, tx_type == 4);
        let (remaining, reservoir) = SEEN.with(Cell::get).expect("the hook ran");
        // The first frame starts on what the hook saw, less the `GAS` instruction's own cost.
        assert_eq!(frame_gas(&default), remaining - 2);
        assert_eq!(reservoir, 0);
    }

    /// A state charge before the first frame is the transaction's: the first frame starts from
    /// what it leaves, and a reverting first frame keeps it charged.
    #[rstest::rstest]
    fn a_state_charge_before_the_first_frame_is_kept(
        #[values(0, 1, 2, 3, 4)] tx_type: u8,
        #[values(false, true)] reverts: bool,
    ) {
        let (charged, ..) = run::<Charge>(tx_type, reverts);
        let (default, ..) = run::<DefaultTxHandlerHooks>(tx_type, reverts);
        assert_eq!(charged.status, !reverts);
        assert_eq!(default.status, !reverts);
        // Below the cap the reservoir is empty: the charge spills into the regular gas.
        assert_eq!(frame_gas(&charged), frame_gas(&default) - CHARGE);
        assert_eq!(charged.total_gas_spent, default.total_gas_spent + CHARGE);
        assert_eq!(charged.state_gas_spent, default.state_gas_spent + CHARGE);
    }

    /// A transaction the hook settles runs no frame: it is included with the result the hook
    /// gave (an out-of-gas burning its execution gas), its nonce bumped, nothing of its frame made
    /// and, for EIP-7702, its delegations rolled back.
    #[rstest::rstest]
    fn a_transaction_settled_before_the_first_frame_runs_none(
        #[values(0, 1, 2, 3, 4)] tx_type: u8,
    ) {
        let mut evm = evm::<Settle>(false);
        let result = evm.transact(&tx(tx_type)).unwrap().commit();
        assert!(!result.status);
        assert_eq!(result.stop, InstrStop::OutOfGas);
        assert_eq!(result.total_gas_spent, GAS_LIMIT);
        assert_eq!(result.state_gas_spent, 0);
        assert!(result.output.is_empty());
        assert_eq!(evm.state.account_info_untracked(&CALLER).unwrap().unwrap().nonce, 1);
        assert_eq!(evm.state.storage_slot(&RECIPIENT, Word::ONE).unwrap().current(), Word::ZERO);
        let authority = evm.state.account_info_untracked(&AUTHORITY).unwrap();
        assert!(authority.as_ref().is_none_or(|info| info.is_empty()), "{authority:?}");
    }
}
