//! The active version's give-back rule for state gas at the instruction sites.
//!
//! EIP-8037 credits a give-back of state gas to the frame's execution gas first, up to the state
//! gas that gas paid; [`EvmFeatures::EIP8037_RESERVOIR_REFILLS`] credits it to the reservoir alone.
//! The opcodes that give state gas back, and those that merge a returning child into their frame,
//! go through these helpers, so a type family's own opcodes follow the same rule.
//!
//! The rule is the interpreter's: the JIT builtins keep EIP-8037's.

use crate::{
    EvmFeatures, EvmTypesHost,
    interpreter::{Gas, GasTracker, InstrStop, InterpreterState},
};

/// Gives `amount` of state gas back to the running frame: into its reservoir alone under
/// [`EvmFeatures::EIP8037_RESERVOIR_REFILLS`] ([`Gas::refill_reservoir_only`]), otherwise
/// EIP-8037's refill ([`Gas::refill_reservoir`]).
#[inline]
pub const fn give_back_state_gas<T: EvmTypesHost>(
    gas: &mut Gas,
    state: &InterpreterState<'_, '_, T>,
    amount: u64,
) {
    if state.feature(EvmFeatures::EIP8037_RESERVOIR_REFILLS) {
        gas.refill_reservoir_only(amount);
    } else {
        gas.refill_reservoir(amount);
    }
}

/// Merges a returning child's settled gas into the running frame: by
/// [`Gas::merge_child_gas_into_reservoir`] under [`EvmFeatures::EIP8037_RESERVOIR_REFILLS`],
/// otherwise by EIP-8037's [`Gas::merge_child_gas`].
#[inline]
pub const fn merge_returned_gas<T: EvmTypesHost>(
    gas: &mut Gas,
    state: &InterpreterState<'_, '_, T>,
    child: GasTracker,
    stop: InstrStop,
) {
    if state.feature(EvmFeatures::EIP8037_RESERVOIR_REFILLS) {
        gas.merge_child_gas_into_reservoir(child, stop);
    } else {
        gas.merge_child_gas(child, stop);
    }
}
