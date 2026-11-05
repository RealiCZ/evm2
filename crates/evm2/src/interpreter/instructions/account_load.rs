//! The account loads of the interpreter's instructions ([`EvmTypesHost::before_account_load`]).
//!
//! Every account an instruction loads passes through the type family's hook first, at the point
//! where the instruction loads it: after the charges the instruction makes before the load, and
//! before the load and its EIP-2929 skip-cold check. A family can refuse a load there with a stop
//! of its own; the default admits every load and compiles to nothing.
//!
//! The seam is interpreter-only: the JIT builtins load accounts without consulting it.

use crate::{
    EvmTypesHost,
    interpreter::{InterpreterState, Result},
};
use alloy_primitives::Address;

/// Offers the load of `address`'s account at `site` to the type family's hook.
#[inline(always)]
pub(crate) fn before_account_load<T: EvmTypesHost>(
    state: &mut InterpreterState<'_, '_, T>,
    address: &Address,
    site: AccountLoadSite,
) -> Result {
    T::before_account_load(state, address, site)
}

/// Where an instruction loads an account ([`EvmTypesHost::before_account_load`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccountLoadSite {
    /// `BALANCE`'s account.
    Balance,
    /// `SELFBALANCE`'s: the running frame's own account.
    SelfBalance,
    /// `EXTCODESIZE`'s account.
    ExtCodeSize,
    /// `EXTCODEHASH`'s account.
    ExtCodeHash,
    /// `EXTCODECOPY`'s account, after the copy and its memory expansion are charged.
    ExtCodeCopy,
    /// The target of `CALL`, `CALLCODE`, `DELEGATECALL` or `STATICCALL`, after the memory
    /// expansion of its ranges and the value-transfer charge.
    CallTarget,
    /// The EIP-7702 delegate of a call's target, after the delegation guard.
    CallDelegate,
    /// The account `SELFDESTRUCT` runs in, which it clears.
    SelfDestructContract,
    /// `SELFDESTRUCT`'s beneficiary.
    SelfDestructTarget,
    /// The creator of a `CREATE` or `CREATE2`, read for its nonce and balance.
    CreateCaller,
    /// The address a `CREATE` or `CREATE2` creates at, read for EIP-8037's account charge.
    CreateDestination,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BaseEvmConfigSelector, Evm, Inspector, SpecId,
        bytecode::Bytecode,
        env::BlockEnv,
        evm::{AccountInfo, InMemoryDB},
        interpreter::{Host, InstrStop, Message, MessageExt, MessageKind, MessageResult, Word, op},
        precompiles::Precompiles,
        registry::TxRegistry,
        test_utils::push_address,
    };
    use alloc::vec::Vec;
    use alloy_primitives::Bytes;

    /// Every load the hook saw, and the account it refuses.
    #[derive(Clone, Debug, Default)]
    struct Loads {
        seen: Vec<(AccountLoadSite, Address, u16)>,
        refuse: Option<Address>,
    }

    struct LoadTypes;

    impl EvmTypesHost for LoadTypes {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = Loads;
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = ();
        type Host<'a> = Evm<'a, Self>;
        type MessageHooks = ();

        fn before_account_load(
            state: &mut InterpreterState<'_, '_, Self>,
            address: &Address,
            site: AccountLoadSite,
        ) -> Result {
            let depth = state.message().depth;
            let loads = state.host().ext_mut();
            loads.seen.push((site, *address, depth));
            if loads.refuse == Some(*address) {
                return Err(InstrStop::InvalidFEOpcode);
            }
            Ok(())
        }
    }

    /// Steps every opcode, so an inspected run takes the inspect table.
    struct Stepping;

    impl Inspector<LoadTypes> for Stepping {}

    const CODE: Address = Address::with_last_byte(0xc0);
    const OTHER: Address = Address::with_last_byte(0xd0);
    const DELEGATING: Address = Address::with_last_byte(0xd7);
    const DELEGATE: Address = Address::with_last_byte(0xde);
    const HEIR: Address = Address::with_last_byte(0xbe);

    /// Runs `code` in `CODE`'s frame on Amsterdam (EIP-7702 and EIP-8037 on), plain or with an
    /// inspector that steps every opcode, refusing `refuse`'s loads.
    fn run(
        code: &[u8],
        gas_limit: u64,
        refuse: Option<Address>,
        inspect: bool,
    ) -> (MessageResult<LoadTypes>, Loads) {
        let spec = SpecId::AMSTERDAM;
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &CODE,
            AccountInfo::default()
                .with_balance(Word::from(10))
                .with_code(Bytecode::new_legacy(Bytes::from(code.to_vec()))),
        );
        db.insert_account_info(
            &OTHER,
            AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(&[op::STOP]))),
        );
        db.insert_account_info(
            &DELEGATING,
            AccountInfo::default().with_code(Bytecode::new_eip7702(DELEGATE)),
        );
        db.insert_account_info(
            &DELEGATE,
            AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(&[op::STOP]))),
        );
        let mut evm = Evm::<LoadTypes>::new_with_ext(
            spec,
            BlockEnv::<LoadTypes>::default(),
            TxRegistry::new(),
            db,
            Precompiles::base(spec),
            Loads { refuse, ..Loads::default() },
        );
        if inspect {
            evm.set_inspector(Stepping);
        }
        let bytecode = evm.state_mut().account(&CODE).unwrap().load_code().unwrap();
        let mut message: Message<LoadTypes> = MessageExt {
            kind: MessageKind::Call,
            gas_limit,
            destination: CODE,
            call_target: CODE,
            caller: Address::with_last_byte(0xee),
            code: bytecode,
            code_address: CODE,
            ..MessageExt::default()
        };
        let result = Host::execute_message(&mut evm, &mut message).unwrap();
        (result, evm.ext().clone())
    }

    /// `op` on `address` with every other operand zero (a call forwards all gas, no value).
    fn load(code: &mut Vec<u8>, opcode: u8, address: &Address) {
        match opcode {
            op::EXTCODECOPY => {
                code.extend([op::PUSH0, op::PUSH0, op::PUSH0]);
                push_address(code, address);
                code.push(opcode);
            }
            op::CALL | op::CALLCODE => {
                code.extend([op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0]);
                push_address(code, address);
                code.extend([op::GAS, opcode, op::POP]);
            }
            op::DELEGATECALL | op::STATICCALL => {
                code.extend([op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0]);
                push_address(code, address);
                code.extend([op::GAS, opcode, op::POP]);
            }
            _ => {
                push_address(code, address);
                code.extend([opcode, op::POP]);
            }
        }
    }

    /// Every account an instruction loads reaches the hook, with its site, in the order the
    /// instructions load them, the same on the plain and the inspected path.
    #[test]
    fn every_instruction_load_reaches_the_hook() {
        let mut code = Vec::new();
        load(&mut code, op::BALANCE, &OTHER);
        code.extend([op::SELFBALANCE, op::POP]);
        load(&mut code, op::EXTCODESIZE, &OTHER);
        load(&mut code, op::EXTCODEHASH, &OTHER);
        load(&mut code, op::EXTCODECOPY, &OTHER);
        for opcode in [op::CALL, op::CALLCODE, op::DELEGATECALL, op::STATICCALL] {
            load(&mut code, opcode, &OTHER);
        }
        load(&mut code, op::CALL, &DELEGATING);
        // CREATE and CREATE2 of empty initcode.
        code.extend([op::PUSH0, op::PUSH0, op::PUSH0, op::CREATE, op::POP]);
        code.extend([op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0, op::CREATE2, op::POP]);
        push_address(&mut code, &HEIR);
        code.push(op::SELFDESTRUCT);

        let created = CODE.create(0);
        let created2 = CODE.create2(alloy_primitives::B256::ZERO, alloy_primitives::keccak256([]));
        use AccountLoadSite::*;
        let expected = [
            (Balance, OTHER),
            (SelfBalance, CODE),
            (ExtCodeSize, OTHER),
            (ExtCodeHash, OTHER),
            (ExtCodeCopy, OTHER),
            (CallTarget, OTHER),
            (CallTarget, OTHER),
            (CallTarget, OTHER),
            (CallTarget, OTHER),
            (CallTarget, DELEGATING),
            (CallDelegate, DELEGATE),
            (CreateCaller, CODE),
            (CreateDestination, created),
            (CreateCaller, CODE),
            (CreateDestination, created2),
            (SelfDestructContract, CODE),
            (SelfDestructTarget, HEIR),
        ]
        .map(|(site, address)| (site, address, 0));
        for inspect in [false, true] {
            let (result, loads) = run(&code, 1_000_000, None, inspect);
            assert_eq!(result.stop, InstrStop::SelfDestruct, "inspect={inspect}");
            assert_eq!(loads.seen, expected, "inspect={inspect}");
        }
    }

    /// A refused load stops its instruction with the hook's stop before the load: a cold account
    /// the frame could not pay for is refused, not skipped, and a refused target's delegate is
    /// never looked up.
    #[test]
    fn a_refused_load_stops_the_instruction_before_the_load() {
        // BALANCE of a cold account with 100 gas left at its body: the skip-cold check would halt
        // it out of gas; the hook runs first and its stop is the frame's.
        let mut code = Vec::new();
        push_address(&mut code, &OTHER);
        code.extend([op::BALANCE, op::STOP]);
        for inspect in [false, true] {
            let (skipped, loads) = run(&code, 203, None, inspect);
            assert_eq!(skipped.stop, InstrStop::OutOfGas, "inspect={inspect}");
            assert_eq!(loads.seen, [(AccountLoadSite::Balance, OTHER, 0)]);

            let (refused, loads) = run(&code, 203, Some(OTHER), inspect);
            assert_eq!(refused.stop, InstrStop::InvalidFEOpcode, "inspect={inspect}");
            assert_eq!(loads.seen, [(AccountLoadSite::Balance, OTHER, 0)]);
        }

        // A refused call target: no delegate lookup.
        let mut code = Vec::new();
        load(&mut code, op::CALL, &DELEGATING);
        code.push(op::STOP);
        for inspect in [false, true] {
            let (refused, loads) = run(&code, 100_000, Some(DELEGATING), inspect);
            assert_eq!(refused.stop, InstrStop::InvalidFEOpcode, "inspect={inspect}");
            assert_eq!(loads.seen, [(AccountLoadSite::CallTarget, DELEGATING, 0)]);
        }

        // A refused delegate: the target was loaded, the delegate is not.
        for inspect in [false, true] {
            let (refused, loads) = run(&code, 100_000, Some(DELEGATE), inspect);
            assert_eq!(refused.stop, InstrStop::InvalidFEOpcode, "inspect={inspect}");
            assert_eq!(
                loads.seen,
                [
                    (AccountLoadSite::CallTarget, DELEGATING, 0),
                    (AccountLoadSite::CallDelegate, DELEGATE, 0)
                ]
            );
        }
    }

    /// The hook runs after the charges an instruction makes before its load: EXTCODECOPY's copy
    /// and memory expansion, a call's memory expansion and value transfer, the delegation guard.
    /// An instruction that fails on one of them never reaches the hook.
    #[test]
    fn the_hook_runs_after_the_charges_before_the_load() {
        let version = crate::Version::new(SpecId::AMSTERDAM);
        let table = crate::OpcodeConfig::<LoadTypes>::base::<
            crate::BaseEvmConfig<{ SpecId::AMSTERDAM as u32 }>,
        >();
        // EXTCODECOPY of 32 bytes into fresh memory: 3 (copy) + 3 (memory) after its static gas;
        // 5 left at the body fails the memory expansion.
        let mut code = Vec::new();
        code.extend([op::PUSH1, 32, op::PUSH0, op::PUSH0]);
        push_address(&mut code, &OTHER);
        code.extend([op::EXTCODECOPY, op::STOP]);
        let static_gas = 3 + 2 + 2 + 3 + u64::from(table.static_gas(op::EXTCODECOPY));
        for inspect in [false, true] {
            let (failed, loads) = run(&code, static_gas + 5, Some(OTHER), inspect);
            assert_eq!(failed.stop, InstrStop::MemoryOOG, "inspect={inspect}");
            assert!(loads.seen.is_empty(), "the memory expansion fails first");
            let (refused, loads) = run(&code, static_gas + 6, Some(OTHER), inspect);
            assert_eq!(refused.stop, InstrStop::InvalidFEOpcode, "inspect={inspect}");
            assert_eq!(loads.seen, [(AccountLoadSite::ExtCodeCopy, OTHER, 0)]);
        }

        // A warm delegating target with less than the delegation's warm read left: the guard
        // halts before the delegate's load is offered.
        let mut code = Vec::new();
        push_address(&mut code, &DELEGATING);
        code.extend([op::BALANCE, op::POP]);
        load(&mut code, op::CALL, &DELEGATING);
        code.push(op::STOP);
        // BALANCE (static and cold) and POP; the call's pushes and static gas: 99 left at its
        // body, under the delegation's 100 warm read.
        let cold = version.gas_params.cold_account_additional_cost();
        let before_call = 3 + u64::from(table.static_gas(op::BALANCE)) + cold + 2 + 5 * 2 + 3 + 2;
        let before_call = before_call + u64::from(table.static_gas(op::CALL));
        for inspect in [false, true] {
            let (guarded, loads) = run(&code, before_call + 99, Some(DELEGATE), inspect);
            assert_eq!(guarded.stop, InstrStop::OutOfGas, "inspect={inspect}");
            assert_eq!(
                loads.seen.last(),
                Some(&(AccountLoadSite::CallTarget, DELEGATING, 0)),
                "the guard fails before the delegate's load"
            );
            let (refused, loads) = run(&code, before_call + 100, Some(DELEGATE), inspect);
            assert_eq!(refused.stop, InstrStop::InvalidFEOpcode, "inspect={inspect}");
            assert_eq!(loads.seen.last(), Some(&(AccountLoadSite::CallDelegate, DELEGATE, 0)));
        }
    }

    /// The hook sees the frame that loads: a child's loads carry the child's depth.
    #[test]
    fn the_hook_sees_the_loading_frame() {
        let mut code = Vec::new();
        load(&mut code, op::CALL, &CODE);
        code.push(op::STOP);
        // `CODE` calls itself until the depth limit stops it; a short run is enough to see two
        // depths.
        let (_, loads) = run(&code, 30_000, None, false);
        assert_eq!(loads.seen[0], (AccountLoadSite::CallTarget, CODE, 0));
        assert_eq!(loads.seen[1], (AccountLoadSite::CallTarget, CODE, 1));
    }
}
