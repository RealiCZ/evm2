//! The running frame's gas reserve ([`EvmTypesHost::gas_reserve`]) at the instruction sites.
//!
//! A type family may hold part of a frame's execution gas outside `remaining`, as a reserve the
//! frame cannot spend on its own execution. The interpreter's budget decisions see it (through
//! [`gas_budget`]), and the deductions that are not the frame's own execution draw it first: the
//! gas a call or creation forwards ([`spend_reserve_first`]) and a state-gas charge spilling past
//! the reservoir ([`spend_state_reserve_first`]). The defaults hold no reserve, so these helpers
//! compile to the stock code.
//!
//! The seam is interpreter-only: the JIT builtins read `remaining` alone and never consult it.

use crate::{
    EvmTypesHost,
    interpreter::{Gas, InterpreterState, Result},
    version::GasId,
};

/// The budget decision a reserve read is made for ([`EvmTypesHost::gas_reserve`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BudgetUse {
    /// The value `GAS` pushes.
    Gas,
    /// Whether an account load may touch a cold account (EIP-2929): the account opcodes, the
    /// call family's target and `SELFDESTRUCT`'s beneficiary.
    ColdAccount,
    /// Whether a storage load may touch a cold slot (EIP-2929): `SLOAD` and `SSTORE`.
    ColdStorage,
    /// The EIP-2200 sentry: `SSTORE` may not run on the call stipend alone.
    SstoreSentry,
    /// Whether a call may load its target's EIP-7702 delegate: the guard on the delegation
    /// charge and the delegate's own cold-load check.
    DelegationGuard,
    /// The base of the gas a call or creation forwards to its child (EIP-150).
    Forward,
}

/// Why a deduction draws the running frame's gas reserve ([`EvmTypesHost::draw_gas_reserve`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReserveDraw {
    /// The gas a call or creation forwards to its child.
    Forward,
    /// A state-gas charge of this schedule entry spilling past the reservoir.
    StateSpill(GasId),
}

/// The gas a budget decision sees: `remaining` plus the running frame's reserve.
#[inline(always)]
pub fn gas_budget<T: EvmTypesHost>(
    gas: &Gas,
    state: &mut InterpreterState<'_, '_, T>,
    use_: BudgetUse,
) -> u64 {
    gas.remaining().saturating_add(T::gas_reserve(state.host(), use_))
}

/// Deducts `amount` that is not the frame's own execution, drawing the reserve first.
#[inline(always)]
pub fn spend_reserve_first<T: EvmTypesHost>(
    gas: &mut Gas,
    state: &mut InterpreterState<'_, '_, T>,
    amount: u64,
    draw: ReserveDraw,
) -> Result {
    draw_reserve::<T>(gas, state.host(), amount, draw);
    gas.spend(amount)
}

/// Charges `cost` of state gas `id`; the part spilling past the reservoir draws the reserve first.
#[inline(always)]
pub fn spend_state_reserve_first<T: EvmTypesHost>(
    gas: &mut Gas,
    state: &mut InterpreterState<'_, '_, T>,
    id: GasId,
    cost: u64,
) -> Result {
    spend_state_reserve_first_on::<T>(gas, state.host(), id, cost)
}

/// [`spend_state_reserve_first`] outside an instruction, on the host directly.
#[inline(always)]
pub(crate) fn spend_state_reserve_first_on<T: EvmTypesHost>(
    gas: &mut Gas,
    host: &mut T::Host<'_>,
    id: GasId,
    cost: u64,
) -> Result {
    draw_reserve::<T>(gas, host, cost.saturating_sub(gas.reservoir()), ReserveDraw::StateSpill(id));
    gas.spend_state(cost)
}

/// Moves up to `amount` of the reserve into `remaining`.
#[inline(always)]
fn draw_reserve<T: EvmTypesHost>(
    gas: &mut Gas,
    host: &mut T::Host<'_>,
    amount: u64,
    draw: ReserveDraw,
) {
    if amount != 0 {
        let drawn = T::draw_gas_reserve(host, amount, draw);
        gas.erase_cost(drawn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BaseEvmConfigSelector, Evm, ExecutionError, Inspector, MessageHooks, SpecId,
        bytecode::Bytecode,
        env::BlockEnv,
        evm::{AccountInfo, InMemoryDB},
        interpreter::{
            GasTracker, Host, InstrStop, Message, MessageExt, MessageKind, MessageResult, Word, op,
        },
        precompiles::Precompiles,
        registry::TxRegistry,
        test_utils::{push, push_address},
    };
    use alloc::vec::Vec;
    use alloy_primitives::{Address, Bytes};

    /// A reserve the whole run shares, with every read, draw, child limit and halt recorded.
    #[derive(Clone, Debug, Default)]
    struct Ledger {
        reserve: u64,
        uses: Vec<BudgetUse>,
        draws: Vec<(ReserveDraw, u64)>,
        child_limits: Vec<u64>,
        /// The first frame's `(halt_remaining, remaining)` at `before_commit`.
        halt: Option<(Option<u64>, u64)>,
    }

    struct ReserveTypes;

    impl EvmTypesHost for ReserveTypes {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = Ledger;
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = ();
        type Host<'a> = Evm<'a, Self>;
        type MessageHooks = Recorder;

        fn gas_reserve(host: &mut Evm<'_, Self>, use_: BudgetUse) -> u64 {
            let ledger = host.ext_mut();
            ledger.uses.push(use_);
            ledger.reserve
        }

        fn draw_gas_reserve(host: &mut Evm<'_, Self>, amount: u64, draw: ReserveDraw) -> u64 {
            let ledger = host.ext_mut();
            let drawn = amount.min(ledger.reserve);
            ledger.reserve -= drawn;
            ledger.draws.push((draw, drawn));
            drawn
        }
    }

    struct Recorder;

    impl MessageHooks<ReserveTypes> for Recorder {
        fn before(
            evm: &mut Evm<'_, ReserveTypes>,
            message: &mut Message<ReserveTypes>,
        ) -> Result<Option<MessageResult<ReserveTypes>>, ExecutionError> {
            if message.depth == 1 {
                evm.ext_mut().child_limits.push(message.gas_limit);
            }
            Ok(None)
        }

        fn before_commit(
            evm: &mut Evm<'_, ReserveTypes>,
            message: &Message<ReserveTypes>,
            _: &mut InstrStop,
            _: &mut Bytes,
            gas: &mut GasTracker,
        ) -> Result<(), ExecutionError> {
            if message.depth == 0 {
                evm.ext_mut().halt = Some((gas.halt_remaining(), gas.remaining()));
            }
            Ok(())
        }
    }

    /// Steps every opcode, so an inspected run takes the inspect table, which zeroes `remaining`
    /// on an out-of-gas step. An inspector that steps nothing runs the plain loop.
    struct Stepping;

    impl Inspector<ReserveTypes> for Stepping {}

    const CODE: Address = Address::with_last_byte(0xc0);
    const OTHER: Address = Address::with_last_byte(0xd0);
    const DELEGATE: Address = Address::with_last_byte(0xde);

    struct Run {
        spec: SpecId,
        code: Vec<u8>,
        gas_limit: u64,
        reservoir: u64,
        kind: MessageKind,
        other: Option<Bytecode>,
    }

    impl Run {
        fn new(spec: SpecId, code: Vec<u8>, gas_limit: u64) -> Self {
            Self { spec, code, gas_limit, reservoir: 0, kind: MessageKind::Call, other: None }
        }

        /// Runs the first frame with `reserve`, plain or inspected.
        fn run(&self, reserve: u64, inspect: bool) -> (MessageResult<ReserveTypes>, Ledger) {
            let mut db = InMemoryDB::default();
            db.insert_account_info(
                &CODE,
                AccountInfo::default()
                    .with_balance(Word::from(10))
                    .with_code(Bytecode::new_legacy(Bytes::from(self.code.clone()))),
            );
            if let Some(code) = &self.other {
                db.insert_account_info(&OTHER, AccountInfo::default().with_code(code.clone()));
            }
            let mut evm = Evm::<ReserveTypes>::new_with_ext(
                self.spec,
                BlockEnv::<ReserveTypes>::default(),
                TxRegistry::new(),
                db,
                Precompiles::base(self.spec),
                Ledger { reserve, ..Ledger::default() },
            );
            if inspect {
                evm.set_inspector(Stepping);
            }
            let (destination, code) = match self.kind {
                MessageKind::Create => {
                    (Address::with_last_byte(0xcc), Bytecode::new_legacy(self.code.clone().into()))
                }
                _ => (CODE, evm.state_mut().account(&CODE).unwrap().load_code().unwrap()),
            };
            let mut message: Message<ReserveTypes> = MessageExt {
                kind: self.kind,
                gas_limit: self.gas_limit,
                reservoir: self.reservoir,
                destination,
                call_target: destination,
                caller: Address::with_last_byte(0xee),
                code,
                code_address: destination,
                ..MessageExt::default()
            };
            let result = Host::execute_message(&mut evm, &mut message).unwrap();
            (result, evm.ext().clone())
        }
    }

    fn word(bytes: &[u8]) -> u64 {
        u64::try_from(Word::from_be_slice(bytes)).unwrap()
    }

    #[test]
    fn gas_pushes_remaining_plus_reserve() {
        let code = [op::GAS, op::PUSH0, op::MSTORE, op::PUSH1, 32, op::PUSH0, op::RETURN];
        let run = Run::new(SpecId::OSAKA, code.to_vec(), 100_000);
        for inspect in [false, true] {
            let (plain, _) = run.run(0, inspect);
            let (reserved, ledger) = run.run(1_000, inspect);
            assert_eq!(word(&plain.output), 99_998, "inspect={inspect}");
            assert_eq!(word(&reserved.output), 100_998, "inspect={inspect}");
            assert!(ledger.uses.contains(&BudgetUse::Gas));
        }
    }

    /// An account load the spendable gas alone would skip: with the reserve it is made, and its
    /// cold charge then fails on the spendable gas.
    #[test]
    fn cold_account_check_sees_reserve() {
        let mut code = Vec::new();
        push_address(&mut code, &OTHER);
        code.extend([op::BALANCE, op::STOP]);
        // 1,000 left at BALANCE's body, under the 2,500 cold surcharge.
        let run = Run::new(SpecId::OSAKA, code, 1_103);
        for inspect in [false, true] {
            let (skipped, ledger) = run.run(0, inspect);
            assert_eq!(skipped.stop, InstrStop::OutOfGas);
            assert_eq!(skipped.gas.failed_charge(), None, "no debit: the load is skipped");
            // The halt's gas is readable on both paths: in `remaining` on the plain path, in the
            // no-debit record on the inspected one, which zeroes `remaining`.
            let expected = if inspect { (Some(1_000), 0) } else { (None, 1_000) };
            assert_eq!(ledger.halt, Some(expected), "inspect={inspect}");

            let (loaded, ledger) = run.run(1_500, inspect);
            assert_eq!(loaded.stop, InstrStop::OutOfGas);
            assert_eq!(loaded.gas.failed_charge(), Some((1_000, 2_500)), "inspect={inspect}");
            assert_eq!(ledger.halt.unwrap().0, Some(1_000));
            assert!(ledger.uses.contains(&BudgetUse::ColdAccount));
        }
    }

    #[test]
    fn cold_storage_check_sees_reserve() {
        let code = vec![op::PUSH1, 1, op::SLOAD, op::STOP];
        // 1,000 left at SLOAD's body, under the 2,000 cold surcharge.
        let run = Run::new(SpecId::OSAKA, code, 1_103);
        for inspect in [false, true] {
            let (skipped, ledger) = run.run(0, inspect);
            assert_eq!(skipped.stop, InstrStop::OutOfGas);
            assert_eq!(skipped.gas.failed_charge(), None);
            assert_eq!(ledger.halt.map(|(r, rem)| r.unwrap_or(rem)), Some(1_000));

            let (loaded, ledger) = run.run(1_000, inspect);
            assert_eq!(loaded.gas.failed_charge(), Some((1_000, 2_000)), "inspect={inspect}");
            assert!(ledger.uses.contains(&BudgetUse::ColdStorage));
        }
    }

    #[test]
    fn sstore_sentry_sees_reserve() {
        let code = vec![op::PUSH1, 1, op::PUSH1, 1, op::SSTORE, op::STOP];
        // 2,300 left at SSTORE's body: the stipend alone.
        let run = Run::new(SpecId::OSAKA, code, 2_306);
        for inspect in [false, true] {
            let (sentry, ledger) = run.run(0, inspect);
            assert_eq!(sentry.stop, InstrStop::ReentrancySentryOOG);
            assert_eq!(ledger.halt.map(|(r, rem)| r.unwrap_or(rem)), Some(2_300));

            // One more gas in the reserve passes the sentry; the slot's set then fails on the
            // spendable 2,200 left after the static charge.
            let (store, ledger) = run.run(1, inspect);
            assert_eq!(store.stop, InstrStop::OutOfGas, "inspect={inspect}");
            assert_eq!(store.gas.failed_charge(), Some((2_200, 22_000)));
            assert!(ledger.uses.contains(&BudgetUse::SstoreSentry));
            assert!(ledger.uses.contains(&BudgetUse::ColdStorage));
        }
    }

    /// SSTORE's cold check: with 2,100 left at the body the sentry needs the reserve, and so does
    /// the cold load after the static charge (2,000 spendable against the 2,000 surcharge).
    #[test]
    fn sstore_cold_storage_check_sees_reserve() {
        let code = vec![op::PUSH1, 1, op::PUSH1, 1, op::SSTORE, op::STOP];
        let run = Run::new(SpecId::OSAKA, code, 2_106);
        for inspect in [false, true] {
            // The reserve lifts both the sentry and the cold check: the slot is loaded and its set
            // fails on the 2,000 spendable gas. A cold check on the spendable gas alone would skip
            // the load and halt without a debit.
            let (store, ledger) = run.run(1_000, inspect);
            assert_eq!(store.stop, InstrStop::OutOfGas, "inspect={inspect}");
            assert_eq!(store.gas.failed_charge(), Some((2_000, 22_000)), "inspect={inspect}");
            assert_eq!(
                ledger.uses.iter().filter(|u| **u == BudgetUse::ColdStorage).count(),
                1,
                "inspect={inspect}"
            );
        }
    }

    /// A call's target load the spendable gas alone would skip.
    #[test]
    fn call_target_cold_check_sees_reserve() {
        let mut code = Vec::new();
        code.extend([op::PUSH0; 5]);
        push_address(&mut code, &OTHER);
        code.extend([op::PUSH0, op::CALL, op::STOP]);
        // 1,000 left at CALL's body, under the 2,500 cold surcharge of its target.
        let run = Run::new(SpecId::OSAKA, code, 1_115);
        for inspect in [false, true] {
            let (skipped, ledger) = run.run(0, inspect);
            assert_eq!(skipped.stop, InstrStop::OutOfGas);
            assert_eq!(skipped.gas.failed_charge(), None, "no debit: the load is skipped");
            assert_eq!(ledger.halt.map(|(r, rem)| r.unwrap_or(rem)), Some(1_000));

            let (loaded, ledger) = run.run(1_500, inspect);
            assert_eq!(loaded.gas.failed_charge(), Some((1_000, 2_500)), "inspect={inspect}");
            assert!(ledger.child_limits.is_empty(), "no child: the charge failed");
        }
    }

    /// SELFDESTRUCT's beneficiary load the spendable gas alone would skip.
    #[test]
    fn selfdestruct_cold_check_sees_reserve() {
        let mut code = Vec::new();
        push_address(&mut code, &OTHER);
        code.push(op::SELFDESTRUCT);
        // 1,000 left at SELFDESTRUCT's body (after its 5,000), under the 2,600 cold access.
        let run = Run::new(SpecId::OSAKA, code, 6_003);
        for inspect in [false, true] {
            let (skipped, ledger) = run.run(0, inspect);
            assert_eq!(skipped.stop, InstrStop::OutOfGas);
            assert_eq!(skipped.gas.failed_charge(), None, "no debit: the load is skipped");
            assert_eq!(ledger.halt.map(|(r, rem)| r.unwrap_or(rem)), Some(1_000));

            let (loaded, _) = run.run(2_000, inspect);
            assert_eq!(loaded.stop, InstrStop::OutOfGas, "inspect={inspect}");
            assert_eq!(
                loaded.gas.failed_charge().map(|(remaining, _)| remaining),
                Some(1_000),
                "the beneficiary is loaded and its charge fails on the spendable gas"
            );
        }
    }

    /// A call of a warm account delegating (EIP-7702) to a cold one.
    #[test]
    fn delegation_guard_sees_reserve() {
        let mut code = Vec::new();
        push_address(&mut code, &OTHER);
        code.extend([op::BALANCE, op::POP]);
        code.extend([op::PUSH0; 5]);
        push_address(&mut code, &OTHER);
        code.extend([op::PUSH0, op::CALL, op::STOP]);
        // 50 left at CALL's body, under the 100 of the delegation's warm read.
        let mut run = Run::new(SpecId::OSAKA, code, 2_770);
        run.other = Some(Bytecode::new_eip7702(DELEGATE));
        for inspect in [false, true] {
            let (refused, ledger) = run.run(0, inspect);
            assert_eq!(refused.stop, InstrStop::OutOfGas);
            assert_eq!(refused.gas.failed_charge(), None, "the guard makes no debit");
            assert_eq!(ledger.halt.map(|(r, rem)| r.unwrap_or(rem)), Some(50));

            // With the reserve the guard passes and the delegate is loaded; the delegation's
            // charges then fail on the spendable gas.
            let (loaded, ledger) = run.run(5_000, inspect);
            assert_eq!(loaded.gas.failed_charge(), Some((50, 2_600)), "inspect={inspect}");
            assert!(ledger.uses.contains(&BudgetUse::DelegationGuard));
        }
    }

    #[test]
    fn call_forward_sees_and_draws_reserve() {
        let mut code = Vec::new();
        code.extend([op::PUSH0; 5]);
        push_address(&mut code, &OTHER);
        push(&mut code, Word::MAX);
        code.extend([op::CALL, op::STOP]);
        // 640,000 left after the cold target's charge: a forward of 630,000.
        let run = Run::new(SpecId::OSAKA, code, 642_616);
        for inspect in [false, true] {
            let (_, plain) = run.run(0, inspect);
            assert_eq!(plain.child_limits, [630_000]);
            let (_, reserved) = run.run(6_400, inspect);
            assert_eq!(reserved.child_limits, [636_300], "inspect={inspect}");
            assert_eq!(reserved.draws, [(ReserveDraw::Forward, 6_400)]);
            assert!(reserved.uses.contains(&BudgetUse::Forward));
        }
    }

    #[test]
    fn create_forward_sees_and_draws_reserve() {
        let code = vec![op::PUSH0, op::PUSH0, op::PUSH0, op::CREATE, op::STOP];
        // 640,000 left after CREATE's 32,000: a forward of 630,000.
        let run = Run::new(SpecId::OSAKA, code, 672_006);
        for inspect in [false, true] {
            let (_, plain) = run.run(0, inspect);
            assert_eq!(plain.child_limits, [630_000]);
            let (_, reserved) = run.run(6_400, inspect);
            assert_eq!(reserved.child_limits, [636_300], "inspect={inspect}");
            assert_eq!(reserved.draws, [(ReserveDraw::Forward, 6_400)]);
        }
    }

    /// Runs `run` with a 1,000 reserve and returns its first draw; the frame keeps the drawn gas.
    fn first_spill(run: &Run) -> (ReserveDraw, u64) {
        let (plain, _) = run.run(0, false);
        let mut first = None;
        for inspect in [false, true] {
            let (reserved, ledger) = run.run(1_000, inspect);
            assert_eq!(reserved.stop, plain.stop, "inspect={inspect}");
            first.get_or_insert(ledger.draws[0]);
            assert_eq!(first, Some(ledger.draws[0]));
        }
        first.unwrap()
    }

    #[test]
    fn sstore_spill_draws_reserve_first() {
        let run = Run::new(
            SpecId::AMSTERDAM,
            vec![op::PUSH1, 1, op::PUSH1, 1, op::SSTORE, op::STOP],
            1_000_000,
        );
        assert_eq!(first_spill(&run), (ReserveDraw::StateSpill(GasId::SstoreSetState), 1_000));
        let (plain, _) = run.run(0, false);
        let (reserved, _) = run.run(1_000, false);
        assert_eq!(reserved.gas.remaining(), plain.gas.remaining() + 1_000);
    }

    #[test]
    fn spill_within_the_reservoir_draws_nothing() {
        let mut run = Run::new(
            SpecId::AMSTERDAM,
            vec![op::PUSH1, 1, op::PUSH1, 1, op::SSTORE, op::STOP],
            1_000_000,
        );
        run.reservoir = 10_000_000;
        let (_, ledger) = run.run(1_000, false);
        assert_eq!(ledger.draws, []);
        assert_eq!(ledger.reserve, 1_000);
    }

    #[test]
    fn value_call_new_account_spill_draws_reserve_first() {
        let mut code = Vec::new();
        code.extend([op::PUSH0; 4]);
        code.extend([op::PUSH1, 1]);
        push_address(&mut code, &OTHER);
        code.extend([op::PUSH0, op::CALL, op::STOP]);
        let run = Run::new(SpecId::AMSTERDAM, code, 10_000_000);
        assert_eq!(first_spill(&run), (ReserveDraw::StateSpill(GasId::NewAccountState), 1_000));
    }

    #[test]
    fn create_spill_draws_reserve_first() {
        let code = vec![op::PUSH0, op::PUSH0, op::PUSH0, op::CREATE, op::STOP];
        let run = Run::new(SpecId::AMSTERDAM, code, 10_000_000);
        assert_eq!(first_spill(&run), (ReserveDraw::StateSpill(GasId::CreateState), 1_000));
    }

    #[test]
    fn selfdestruct_new_account_spill_draws_reserve_first() {
        let mut code = Vec::new();
        push_address(&mut code, &OTHER);
        code.push(op::SELFDESTRUCT);
        let run = Run::new(SpecId::AMSTERDAM, code, 10_000_000);
        assert_eq!(first_spill(&run), (ReserveDraw::StateSpill(GasId::NewAccountState), 1_000));
        let (plain, _) = run.run(0, false);
        let (reserved, _) = run.run(1_000, false);
        assert_eq!(reserved.gas.remaining(), plain.gas.remaining() + 1_000);
    }

    #[test]
    fn code_deposit_spill_draws_reserve_first() {
        let mut run =
            Run::new(SpecId::AMSTERDAM, vec![op::PUSH1, 1, op::PUSH0, op::RETURN], 10_000_000);
        run.kind = MessageKind::Create;
        assert_eq!(first_spill(&run), (ReserveDraw::StateSpill(GasId::CodeDepositState), 1_000));
        let (plain, _) = run.run(0, false);
        let (reserved, _) = run.run(1_000, false);
        assert_eq!(reserved.gas.remaining(), plain.gas.remaining() + 1_000);
    }

    /// A stock family's no-debit halt (a skipped cold load) settles to equal gas on the plain and
    /// the stepped path: the halt record the stepped path keeps is not part of the gas's equality
    /// or hash.
    #[test]
    fn stock_no_debit_halt_settles_equal_on_both_paths() {
        use crate::BaseEvmTypes;
        use core::hash::BuildHasher;
        struct StepAll;
        impl Inspector<BaseEvmTypes> for StepAll {}

        let mut code = Vec::new();
        push_address(&mut code, &OTHER);
        code.extend([op::BALANCE, op::STOP]);
        let run = |inspect: bool| {
            let mut db = InMemoryDB::default();
            db.insert_account_info(
                &CODE,
                AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from(code.clone()))),
            );
            let mut evm = Evm::<BaseEvmTypes>::new_with_ext(
                SpecId::OSAKA,
                BlockEnv::<BaseEvmTypes>::default(),
                TxRegistry::new(),
                db,
                Precompiles::base(SpecId::OSAKA),
                (),
            );
            if inspect {
                evm.set_inspector(StepAll);
            }
            let code = evm.state_mut().account(&CODE).unwrap().load_code().unwrap();
            let mut message: Message<BaseEvmTypes> = MessageExt {
                kind: MessageKind::Call,
                // 1,000 left at BALANCE's body, under the cold surcharge: the load is skipped.
                gas_limit: 1_103,
                destination: CODE,
                call_target: CODE,
                caller: Address::with_last_byte(0xee),
                code,
                code_address: CODE,
                ..MessageExt::default()
            };
            Host::execute_message(&mut evm, &mut message).unwrap()
        };
        let (plain, stepped) = (run(false), run(true));
        assert_eq!((plain.stop, stepped.stop), (InstrStop::OutOfGas, InstrStop::OutOfGas));
        assert_eq!(stepped.gas.halt_remaining(), Some(1_000), "the stepped path keeps the record");
        assert_eq!(plain.gas, stepped.gas);
        let hasher = alloy_primitives::map::DefaultHashBuilder::default();
        assert_eq!(hasher.hash_one(plain.gas), hasher.hash_one(stepped.gas));
        assert_eq!(plain, stepped, "the message results compare equal");
    }
}
