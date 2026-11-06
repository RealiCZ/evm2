//! Transaction handler extension points.

use crate::{
    Evm, EvmTypes, TxResult,
    interpreter::{GasTracker, MessageResult},
    registry::HandlerResult,
};
use alloy_primitives::{Address, U256};
use derive_where::derive_where;

/// Values produced by transaction execution and consumed during gas settlement.
#[derive_where(Debug)]
pub struct GasSettlement<T: EvmTypes> {
    /// Transaction sender.
    pub caller: Address,
    /// Effective gas price used for this transaction.
    pub gas_price: U256,
    /// Transaction gas limit.
    pub gas_limit: u64,
    /// Calldata floor gas.
    pub floor_gas: u64,
    /// State gas charged before execution.
    pub initial_state_gas: u64,
    /// State gas refunded by pre-execution processing.
    pub state_refund: u64,
    /// Result of executing the top-level message, carrying the settled transaction-level gas
    /// ([`settle_initial_frame_gas`](crate::ethereum::settle_initial_frame_gas)).
    pub result: MessageResult<T>,
}

/// Static extension points shared by transaction handlers.
pub trait TxHandlerHooks<T: EvmTypes>: Sized {
    /// Adjusts the intrinsic execution gas, state gas, and floor gas calculated by the standard
    /// handler before gas-limit validation. The adjusted floor gas is also used during settlement.
    fn adjust_intrinsic_gas(
        _host: &mut Evm<'_, T>,
        _envelope: &T::Tx,
        _intrinsic: &mut u64,
        _initial_state_gas: &mut u64,
        _floor_gas: &mut u64,
    ) -> HandlerResult<()> {
        Ok(())
    }

    /// Runs after standard pre-execution state changes and immediately before the execution
    /// checkpoint is created.
    fn before_execution(
        host: &mut Evm<'_, T>,
        _envelope: &T::Tx,
        caller: Address,
        upfront_fee: U256,
    ) -> HandlerResult<()> {
        crate::ethereum::charge_upfront(host, caller, upfront_fee)?;
        Ok(())
    }

    /// Runs after the standard pre-execution state changes and the transaction environment,
    /// immediately before the first frame is prepared ([`prepare_initial_frame`]), on the
    /// transaction-level gas `tx_gas` the first frame's runtime gas phase starts from.
    ///
    /// A type family may charge gas there before the first frame: a charge on `tx_gas` (state gas
    /// with [`GasTracker::spend_state`], whose spill a reservoir the first frame returns unwinds
    /// first) is the transaction's own, kept whatever the first frame's execution does, and the
    /// first frame starts from what it leaves. A first frame whose runtime gas phase then runs out
    /// of gas settles from the gas the transaction started with, dropping the charge with the
    /// phase's own ([`execute_initial_frame`]).
    ///
    /// Or it may settle the transaction without a frame by returning its result, such as an
    /// included out-of-gas ([`runtime_oog_result`](crate::ethereum::runtime_oog_result)), which
    /// [`Self::settle_transaction`] then settles as a first frame's. An EIP-7702 transaction runs
    /// it after its authorizations are applied, and one settled here keeps none of them, as on a
    /// runtime out-of-gas.
    ///
    /// The default charges nothing and runs the first frame.
    ///
    /// [`prepare_initial_frame`]: crate::ethereum::prepare_initial_frame
    /// [`execute_initial_frame`]: crate::ethereum::execute_initial_frame
    #[inline]
    fn before_initial_frame(
        _host: &mut Evm<'_, T>,
        _envelope: &T::Tx,
        _tx_gas: &mut GasTracker,
    ) -> HandlerResult<Option<MessageResult<T>>> {
        Ok(None)
    }

    /// Settles a transaction after execution and rollback handling.
    fn settle_transaction(
        host: &mut Evm<'_, T>,
        _envelope: &T::Tx,
        gas: GasSettlement<T>,
    ) -> HandlerResult<TxResult<T>> {
        crate::ethereum::default_settle_gas(host, gas)
    }
}

/// Hooks that preserve the default transaction behavior.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultTxHandlerHooks;

impl<T: EvmTypes> TxHandlerHooks<T> for DefaultTxHandlerHooks {}
