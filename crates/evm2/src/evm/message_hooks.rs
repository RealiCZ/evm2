//! Static consensus and observation hooks for the message lifecycle.

use crate::{
    EvmTypesHost, ExecutionError,
    interpreter::{GasTracker, InstrStop, Message, MessageResult},
};
use alloy_primitives::Bytes;

/// Message hooks that carry consensus rules.
///
/// Unlike [`crate::InterpreterRunner`] and [`crate::Inspector`], these run for every message on the
/// plain and the inspected path alike, including messages answered without an interpreter frame
/// (call depth, out of funds, precompiles, accounts without code). A message an inspector answers
/// in `call`/`create` reaches only [`Self::enter`] and [`Self::exit`]. A message that halts
/// without executing ([`crate::Evm::execute_halted_message`], a first frame whose runtime gas phase
/// ran out of gas) reaches none of them, on either path.
///
/// Selected statically by [`EvmTypesHost::MessageHooks`]. Hooks keep per-instance state in
/// [`crate::Evm::ext_mut`]; `()` is the no-op implementation. Execution errors abort the
/// transaction and roll back the message checkpoint. Consensus hooks do not run for inspector
/// overrides.
///
/// The input of a call instruction's message is a range of the caller's memory
/// ([`MessageInput`](crate::interpreter::MessageInput)). Every hook runs while the caller is the
/// running frame, before the callee's frame is entered or after it returns, so
/// [`Evm::message_input`](crate::Evm::message_input) reads the input in any of them. A clone of a
/// range is only the range: a hook that keeps the bytes copies them.
pub trait MessageHooks<T: EvmTypesHost>: 'static {
    /// Whether [`Self::before`] runs.
    ///
    /// `before` gets the message by `&mut` and may keep its input, and a kept range of the
    /// caller's memory reads whatever the caller writes there later, so the message path copies
    /// a call input that is such a range into owned bytes before it runs `before`; `before` and
    /// every hook after it see the copy, and so does the callee. A family that does not override
    /// `before` can set this to `false`: the path then skips both, and the input stays a range of
    /// the caller's memory.
    const RUNS_BEFORE: bool = true;

    /// Runs before the message executes, before the call-depth check.
    ///
    /// Returning `Some(result)` answers the message without executing it; the result is settled
    /// for its stop like any other. The message's input owns its bytes.
    #[inline]
    fn before(
        evm: &mut T::Host<'_>,
        message: &mut Message<T>,
    ) -> Result<Option<MessageResult<T>>, ExecutionError> {
        let _ = (evm, message);
        Ok(None)
    }

    /// Runs once the message's start is made: after its checkpoint, its value transfer and, for a
    /// creation, the creator's nonce bump and the created account, before a precompile, an
    /// account without code or the interpreter answers it.
    ///
    /// Returning `Some((stop, output))` ends the message with `stop` and `output` on its untouched
    /// gas; a stop that is not a success rolls the start back.
    #[inline]
    fn started(
        evm: &mut T::Host<'_>,
        message: &Message<T>,
    ) -> Result<Option<(InstrStop, Bytes)>, ExecutionError> {
        let _ = (evm, message);
        Ok(None)
    }

    /// Runs after an interpreter frame is built, before it is entered: before inspector
    /// initialization or execution, while the caller is still the running frame.
    ///
    /// Not called for precompiles, empty code, or other results without an interpreter.
    #[inline]
    fn frame_built(_host: &mut T::Host<'_>, _message: &Message<T>, _gas: &mut GasTracker) {}

    /// Runs on every built-in result decided after the message's checkpoint, before evm2 commits
    /// or rolls back: an interpreter frame's (after a creation's code-deposit checks and charges),
    /// a precompile's, an account without code's, a call's out-of-funds answer and a creation's
    /// failure to create its account (a collision, an endowment the creator cannot pay). A result
    /// decided before the checkpoint (a call or creation too deep, a creation's balance or nonce
    /// pre-access failure) does not reach it.
    ///
    /// The hook may rewrite the stop, the output and the gas; a stop rewritten to a failure rolls
    /// the message back. Synthetic `before` and `started` answers bypass this hook.
    #[inline]
    fn before_commit(
        evm: &mut T::Host<'_>,
        message: &Message<T>,
        stop: &mut InstrStop,
        output: &mut Bytes,
        gas: &mut GasTracker,
    ) -> Result<(), ExecutionError> {
        let _ = (evm, message, stop, output, gas);
        Ok(())
    }

    /// Runs on built-in and consensus-synthetic results after settlement, before caller merge.
    #[inline]
    fn after(
        evm: &mut T::Host<'_>,
        message: &Message<T>,
        result: &mut MessageResult<T>,
    ) -> Result<(), ExecutionError> {
        let _ = (evm, message, result);
        Ok(())
    }

    /// Observes every message entry, including inspector overrides and execution errors.
    ///
    /// It runs before the message path copies the input for [`Self::before`], so a call's input
    /// can be a range of the caller's memory. A message this hook runs through the host gets the
    /// inspector's hooks, which can change that memory, and the entered message's input then
    /// reads what they leave.
    #[inline]
    fn enter(_host: &mut T::Host<'_>, _message: &Message<T>) {}

    /// Observes a built-in result after commit/rollback, before its gas is settled.
    ///
    /// This observation cannot change the commit decision. It also sees synthetic `before`
    /// answers, but not inspector overrides or execution errors.
    #[inline]
    fn unsettled(_host: &mut T::Host<'_>, _message: &Message<T>, _result: &MessageResult<T>) {}

    /// Observes every message exit, after settlement and inspector end hooks.
    ///
    /// Paired with [`Self::enter`] even for inspector overrides or execution errors. On errors,
    /// the message checkpoint has already been rolled back.
    #[inline]
    fn exit(
        _host: &mut T::Host<'_>,
        _message: &Message<T>,
        _result: &Result<MessageResult<T>, ExecutionError>,
    ) {
    }
}

impl<T: EvmTypesHost> MessageHooks<T> for () {
    const RUNS_BEFORE: bool = false;
}
