//! Ethereum transaction envelope and handlers.

/// EIP-1559 transaction handler.
pub mod eip1559;
/// EIP-2930 transaction handler.
pub mod eip2930;
/// EIP-4844 transaction handler.
pub mod eip4844;
/// EIP-7702 transaction handler.
pub mod eip7702;
mod lazy_eip7702;
/// Legacy transaction handler.
pub mod legacy;

pub use lazy_eip7702::{LazyAuthorization, LazyTxEip7702};

use crate::{
    Evm, EvmFeatures, EvmTypes, HostError, SpecId, TxResult, TxResultExt, Version,
    bytecode::Bytecode,
    evm::{
        AccountInfo,
        handler::{DefaultTxHandlerHooks, GasSettlement},
    },
    interpreter::{
        GasTracker, Host, InstrStop, Message, MessageExt, MessageKind, MessageResult,
        MessageResultExt, gas::WARM_STORAGE_READ_COST,
    },
    registry::{HandlerError, HandlerResult, TxRegistry, handler},
    utils::{b256_to_word, num_words},
    version::{GasId, StateGasSite},
};
use alloy_consensus::{
    EthereumTxEnvelope, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy,
    transaction::{Recovered, Transaction, TxEip4844Variant},
};
use alloy_eips::{eip2718::Typed2718, eip2930::AccessList};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};

/// Ethereum transaction envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxEnvelope {
    /// Legacy transaction.
    Legacy(TxLegacy),
    /// EIP-2930 access-list transaction.
    Eip2930(TxEip2930),
    /// EIP-1559 dynamic-fee transaction.
    Eip1559(TxEip1559),
    /// EIP-4844 blob transaction.
    Eip4844(TxEip4844Variant),
    /// EIP-7702 set-code transaction.
    Eip7702(LazyTxEip7702),
}

/// Recovered Ethereum transaction envelope.
pub type RecoveredTxEnvelope = Recovered<TxEnvelope>;

/// Transaction state produced by validation and pre-execution processing for the standard
/// Ethereum handlers.
#[derive(Clone, Copy, Debug)]
pub struct PreparedTx {
    pub(super) caller: Address,
    pub(super) gas_price: U256,
    pub(super) intrinsic: u64,
    pub(super) initial_state_gas: u64,
    pub(super) floor_gas: u64,
    pub(super) sender_nonce: u64,
}

impl From<EthereumTxEnvelope<TxEip4844>> for TxEnvelope {
    fn from(tx: EthereumTxEnvelope<TxEip4844>) -> Self {
        match tx {
            EthereumTxEnvelope::Legacy(tx) => Self::Legacy(tx.strip_signature()),
            EthereumTxEnvelope::Eip2930(tx) => Self::Eip2930(tx.strip_signature()),
            EthereumTxEnvelope::Eip1559(tx) => Self::Eip1559(tx.strip_signature()),
            EthereumTxEnvelope::Eip4844(tx) => Self::Eip4844(tx.strip_signature().into()),
            EthereumTxEnvelope::Eip7702(tx) => {
                Self::Eip7702(LazyTxEip7702::from_recovered_authorizations(tx.strip_signature()))
            }
        }
    }
}

impl TxEnvelope {
    /// Returns the contained legacy transaction, if this is legacy.
    pub const fn as_legacy(&self) -> Option<&TxLegacy> {
        match self {
            Self::Legacy(tx) => Some(tx),
            Self::Eip2930(_) | Self::Eip1559(_) | Self::Eip4844(_) | Self::Eip7702(_) => None,
        }
    }

    /// Returns the contained EIP-2930 transaction, if this is EIP-2930.
    pub const fn as_eip2930(&self) -> Option<&TxEip2930> {
        match self {
            Self::Eip2930(tx) => Some(tx),
            Self::Legacy(_) | Self::Eip1559(_) | Self::Eip4844(_) | Self::Eip7702(_) => None,
        }
    }

    /// Returns the contained EIP-1559 transaction, if this is EIP-1559.
    pub const fn as_eip1559(&self) -> Option<&TxEip1559> {
        match self {
            Self::Eip1559(tx) => Some(tx),
            Self::Legacy(_) | Self::Eip2930(_) | Self::Eip4844(_) | Self::Eip7702(_) => None,
        }
    }

    /// Returns the contained EIP-4844 transaction, if this is EIP-4844.
    pub const fn as_eip4844(&self) -> Option<&TxEip4844Variant> {
        match self {
            Self::Eip4844(tx) => Some(tx),
            Self::Legacy(_) | Self::Eip2930(_) | Self::Eip1559(_) | Self::Eip7702(_) => None,
        }
    }

    /// Returns the contained EIP-7702 transaction, if this is EIP-7702.
    pub const fn as_eip7702(&self) -> Option<&LazyTxEip7702> {
        match self {
            Self::Eip7702(tx) => Some(tx),
            Self::Legacy(_) | Self::Eip2930(_) | Self::Eip1559(_) | Self::Eip4844(_) => None,
        }
    }
}

impl From<TxEip7702> for TxEnvelope {
    fn from(tx: TxEip7702) -> Self {
        Self::Eip7702(tx.into())
    }
}

impl From<LazyTxEip7702> for TxEnvelope {
    fn from(tx: LazyTxEip7702) -> Self {
        Self::Eip7702(tx)
    }
}

macro_rules! delegate {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            Self::Legacy(tx) => tx.$method($($arg),*),
            Self::Eip2930(tx) => tx.$method($($arg),*),
            Self::Eip1559(tx) => tx.$method($($arg),*),
            Self::Eip4844(tx) => tx.$method($($arg),*),
            Self::Eip7702(tx) => tx.$method($($arg),*),
        }
    };
}

impl Typed2718 for TxEnvelope {
    fn ty(&self) -> u8 {
        delegate!(self, ty)
    }
}

impl Transaction for TxEnvelope {
    fn chain_id(&self) -> Option<u64> {
        delegate!(self, chain_id)
    }

    fn nonce(&self) -> u64 {
        delegate!(self, nonce)
    }

    fn gas_limit(&self) -> u64 {
        delegate!(self, gas_limit)
    }

    fn gas_price(&self) -> Option<u128> {
        delegate!(self, gas_price)
    }

    fn max_fee_per_gas(&self) -> u128 {
        delegate!(self, max_fee_per_gas)
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        delegate!(self, max_priority_fee_per_gas)
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        delegate!(self, max_fee_per_blob_gas)
    }

    fn priority_fee_or_price(&self) -> u128 {
        delegate!(self, priority_fee_or_price)
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        delegate!(self, effective_gas_price, base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        delegate!(self, is_dynamic_fee)
    }

    fn kind(&self) -> TxKind {
        delegate!(self, kind)
    }

    fn is_create(&self) -> bool {
        delegate!(self, is_create)
    }

    fn value(&self) -> U256 {
        delegate!(self, value)
    }

    fn input(&self) -> &Bytes {
        delegate!(self, input)
    }

    fn access_list(&self) -> Option<&AccessList> {
        delegate!(self, access_list)
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        delegate!(self, blob_versioned_hashes)
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        delegate!(self, authorization_list)
    }
}

/// Returns the Ethereum transaction registry for `spec_id`.
pub fn ethereum_tx_registry<T: EvmTypes<Tx = TxEnvelope>>(
    spec_id: SpecId,
) -> TxRegistry<T, TxResult<T>> {
    let mut registry = TxRegistry::new().with_handler(
        0,
        TxEnvelope::as_legacy,
        handler(
            legacy::prepare_with_hooks::<T, DefaultTxHandlerHooks>,
            legacy::execute_prepared::<T, DefaultTxHandlerHooks>,
        ),
    );

    if spec_id.enables(SpecId::BERLIN) {
        registry.register(
            1,
            TxEnvelope::as_eip2930,
            handler(
                eip2930::prepare_with_hooks::<T, DefaultTxHandlerHooks>,
                eip2930::execute_prepared::<T, DefaultTxHandlerHooks>,
            ),
        );
    }
    if spec_id.enables(SpecId::LONDON) {
        registry.register(
            2,
            TxEnvelope::as_eip1559,
            handler(
                eip1559::prepare_with_hooks::<T, DefaultTxHandlerHooks>,
                eip1559::execute_prepared::<T, DefaultTxHandlerHooks>,
            ),
        );
    }
    if spec_id.enables(SpecId::CANCUN) {
        registry.register(
            3,
            TxEnvelope::as_eip4844,
            handler(
                eip4844::prepare_with_hooks::<T, DefaultTxHandlerHooks>,
                eip4844::execute_prepared::<T, DefaultTxHandlerHooks>,
            ),
        );
    }
    if spec_id.enables(SpecId::PRAGUE) {
        registry.register(
            4,
            TxEnvelope::as_eip7702,
            handler(
                eip7702::prepare_with_hooks::<T, DefaultTxHandlerHooks>,
                eip7702::execute_prepared::<T, DefaultTxHandlerHooks>,
            ),
        );
    }

    registry
}

/// Validates the effective gas price against the block base fee.
pub fn validate_gas_price(version: &Version, gas_price: U256, basefee: U256) -> HandlerResult<()> {
    if version.feature(EvmFeatures::BASE_FEE_CHECK) && gas_price < basefee {
        return Err(HandlerError::FeeCapLessThanBaseFee {
            max_fee_per_gas: gas_price,
            base_fee: basefee,
        });
    }
    Ok(())
}

/// Validates that the priority fee does not exceed the maximum fee.
pub fn validate_priority_fee(
    version: &Version,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
) -> HandlerResult<()> {
    if version.feature(EvmFeatures::PRIORITY_FEE_CHECK)
        && max_priority_fee_per_gas > max_fee_per_gas
    {
        return Err(HandlerError::PriorityFeeGreaterThanMaxFee);
    }
    Ok(())
}

/// Calculates the effective gas price for an EIP-1559 transaction.
pub fn effective_gas_price(
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    basefee: U256,
) -> U256 {
    max_fee_per_gas.min(basefee.saturating_add(max_priority_fee_per_gas))
}

/// Validates the transaction gas limit against the block gas limit.
pub fn validate_block_gas_limit(
    version: &Version,
    tx_gas_limit: u64,
    block_gas_limit: U256,
) -> HandlerResult<()> {
    if version.feature(EvmFeatures::BLOCK_GAS_LIMIT_CHECK)
        && U256::from(tx_gas_limit) > block_gas_limit
    {
        return Err(HandlerError::GasLimitMoreThanBlock {
            gas_limit: tx_gas_limit,
            block_gas_limit,
        });
    }
    Ok(())
}

/// Validates the transaction gas limit against the active transaction gas limit cap.
///
/// See [`Version::tx_gas_caps`].
pub const fn validate_tx_gas_limit_cap(version: &Version, tx_gas_limit: u64) -> HandlerResult<()> {
    let (cap, _) = version.tx_gas_caps();
    if tx_gas_limit > cap {
        return Err(HandlerError::TxGasLimitGreaterThanCap { gas_limit: tx_gas_limit, cap });
    }
    Ok(())
}

/// Validates the execution-gas portion against the active execution gas cap.
///
/// See [`Version::tx_gas_caps`].
pub const fn validate_execution_gas_limit_cap(
    version: &Version,
    tx_gas_limit: u64,
    intrinsic: u64,
    floor_gas: u64,
) -> HandlerResult<()> {
    let (_, cap) = version.tx_gas_caps();
    if tx_gas_limit > cap {
        let required_execution_gas = if intrinsic > floor_gas { intrinsic } else { floor_gas };
        if required_execution_gas > cap {
            return Err(HandlerError::IntrinsicGasGreaterThanCap {
                required: required_execution_gas,
                cap,
            });
        }
    }
    Ok(())
}

/// Validates a transaction chain ID against the active chain.
pub const fn validate_chain_id(
    version: &Version,
    chain_id: Option<u64>,
    allow_missing: bool,
) -> HandlerResult<()> {
    if !version.feature(EvmFeatures::TX_CHAIN_ID_CHECK) {
        return Ok(());
    }
    let Some(chain_id) = chain_id else {
        return if allow_missing { Ok(()) } else { Err(HandlerError::MissingChainId) };
    };
    if chain_id != version.chain_id {
        return Err(HandlerError::InvalidChainId { expected: version.chain_id, got: chain_id });
    }
    Ok(())
}

/// Validates top-level create initcode against the active size limit.
pub fn validate_create_initcode(version: &Version, to: TxKind, input: &Bytes) -> HandlerResult<()> {
    if version.feature(EvmFeatures::EIP3860)
        && to.is_create()
        && input.len() > version.max_initcode_size
    {
        return Err(HandlerError::CreateInitCodeSizeLimit {
            limit: version.max_initcode_size,
            got: input.len(),
        });
    }
    Ok(())
}

/// Rejects a nonce that cannot be incremented.
pub const fn validate_nonce_not_overflow(nonce: u64) -> HandlerResult<()> {
    if nonce == u64::MAX {
        return Err(HandlerError::NonceOverflow);
    }
    Ok(())
}

/// Validates that the gas limit covers execution and state intrinsic gas.
pub const fn validate_intrinsic_gas(
    gas_limit: u64,
    intrinsic: u64,
    initial_state_gas: u64,
) -> HandlerResult<()> {
    // EIP-8037: the gas limit must cover the execution intrinsic gas plus the upfront state gas.
    let required = intrinsic.saturating_add(initial_state_gas);
    if gas_limit < required {
        return Err(HandlerError::IntrinsicGasTooLow { required, got: gas_limit });
    }
    Ok(())
}

/// Validates that the gas limit covers the calldata floor gas.
pub const fn validate_floor_gas(gas_limit: u64, floor_gas: u64) -> HandlerResult<()> {
    if gas_limit < floor_gas {
        return Err(HandlerError::GasLimitBelowFloor { required: floor_gas, got: gas_limit });
    }
    Ok(())
}

/// Loads and validates the sender account, then marks it warm and bumps its nonce.
/// Returns the sender's pre-bump state nonce.
///
/// One account handle does all three, so the sender is looked up and journaled once.
pub fn validate_sender_and_bump_nonce<'a, T: EvmTypes>(
    host: &mut Evm<'a, T>,
    caller: Address,
    nonce: u64,
    max_upfront: U256,
) -> HandlerResult<u64> {
    let has_nonce_check = host.feature(EvmFeatures::NONCE_CHECK);
    let has_balance_check = host.feature(EvmFeatures::BALANCE_CHECK);
    let has_balance_top_up = host.feature(EvmFeatures::BALANCE_TOP_UP);
    let has_eip3607 = host.feature(EvmFeatures::EIP3607);

    let mut sender = host.state.account(&caller)?;
    if has_eip3607 && !sender.is_empty_code_hash() {
        let code = sender.load_code()?;
        if !code.is_empty() && !code.is_eip7702() {
            return Err(HandlerError::RejectCallerWithCode);
        }
    }
    if has_nonce_check && sender.nonce() != nonce {
        return Err(HandlerError::InvalidNonce { expected: sender.nonce(), got: nonce });
    }
    if has_balance_check && sender.balance() < max_upfront {
        return Err(HandlerError::InsufficientFunds {
            fee: max_upfront,
            balance: sender.balance(),
        });
    }
    if !has_balance_check && has_balance_top_up && sender.balance() < max_upfront {
        sender.add_balance(max_upfront - sender.balance());
    }
    // The sender is warm from the start of the transaction (EIP-2929).
    sender.warm();
    let sender_nonce = sender.nonce();
    sender.bump_nonce();
    Ok(sender_nonce)
}

/// Warms the accounts required by every transaction other than the sender, which
/// [`validate_sender_and_bump_nonce`] warms.
pub fn warm_base_accounts<'a, T: EvmTypes>(host: &mut Evm<'a, T>, to: TxKind) {
    if host.feature(EvmFeatures::EIP3651) {
        host.state.prewarm(&host.block.beneficiary);
    }
    if let TxKind::Call(to) = to {
        host.state.prewarm(&to);
    }
    host.warm_precompiles();
}

/// Warms every account and storage key in an access list.
pub fn warm_access_list<'a, T: EvmTypes>(host: &mut Evm<'a, T>, access_list: &AccessList) {
    for item in access_list.iter() {
        host.state
            .prewarm_storage(&item.address, item.storage_keys.iter().map(|key| b256_to_word(*key)));
    }
}

/// Deducts a transaction's upfront native-token gas charge.
pub fn charge_upfront<'a, T: EvmTypes>(
    host: &mut Evm<'a, T>,
    caller: Address,
    max_gas_cost: U256,
) -> HandlerResult<()> {
    if !host.feature(EvmFeatures::FEE_CHARGE) {
        return Ok(());
    }
    let mut account = host.state.account(&caller)?;
    let balance = account.balance().saturating_sub(max_gas_cost);
    account.set_balance(balance);
    Ok(())
}

/// Returns `(execution_gas_limit, reservoir)` for the first frame.
///
/// `initial_state_gas` is the EIP-8037 state gas charged at the intrinsic phase (the pre-EIP-2780
/// pessimistic EIP-7702 authorization state gas, or hook-added charges). It is deducted from the
/// reservoir, spilling into the execution budget when the reservoir is insufficient. It is zero
/// without EIP-8037; under EIP-2780 the state-dependent charges are metered at the runtime gas
/// phase instead ([`prepare_initial_frame`]). The pre-EIP-2780 EIP-7702 state-gas refund is not an
/// input here: per execution-specs it is credited directly back to the reservoir after the
/// authorizations are applied, not applied to execution gas first.
pub fn initial_gas_and_reservoir(
    version: &Version,
    tx_gas_limit: u64,
    intrinsic: u64,
    initial_state_gas: u64,
) -> (u64, u64) {
    if !version.feature(EvmFeatures::EIP8037) {
        return (tx_gas_limit - intrinsic, 0);
    }

    let cap = version.tx_gas_limit_cap;
    let execution_gas = tx_gas_limit - intrinsic;
    let mut execution_gas_limit = core::cmp::min(tx_gas_limit, cap).saturating_sub(intrinsic);
    let mut reservoir = execution_gas - execution_gas_limit;

    if reservoir >= initial_state_gas {
        reservoir -= initial_state_gas;
    } else {
        execution_gas_limit -= initial_state_gas - reservoir;
        reservoir = 0;
    }

    (execution_gas_limit, reservoir)
}

/// The first frame of a transaction, prepared by [`prepare_initial_frame`].
#[derive(Clone, Debug)]
pub struct InitialFrame<T: EvmTypes> {
    /// Top-level call or create message, carrying the resolved bytecode to run unless
    /// [`runtime_oog`](Self::runtime_oog).
    pub message: Message<T>,
    /// EIP-8037 state gas charged on the transaction-level tracker for the account leaf this
    /// frame creates (the call recipient's new-account charge or the create target's
    /// account-creation charge), zero when nothing was charged. Refunded by
    /// [`settle_initial_frame_gas`] when the frame fails and the leaf is not created.
    pub charged_state_gas: u64,
    /// The part of [`charged_state_gas`](Self::charged_state_gas) the reservoir paid: all the
    /// reservoir-only rule ([`EvmFeatures::EIP8037_RESERVOIR_REFILLS`]) gives back when the frame
    /// halts.
    pub charged_state_gas_from_reservoir: u64,
    /// Whether the runtime gas phase ran out of gas, so the frame halts without executing
    /// ([`execute_initial_frame`]). Its message then carries no resolved bytecode.
    pub runtime_oog: bool,
}

/// Completes the EIP-2780 runtime gas phase on the transaction-level `tx_gas` and builds the
/// first frame — the depth-0 analog of the CALL/CREATE opcodes' account-load-and-charge step.
///
/// For a call, the recipient pays the new-account state gas when the call transfers value to an
/// empty recipient (charged before the delegation resolution, matching the spec's
/// `prepare_dispatch` order), and a delegated recipient pays the delegation-target access
/// following the EIP-2929 warm/cold model: the warm cost lands before the target load and the
/// cold premium after it, with the load gated on `skip_cold_load` (as nested calls do) so a
/// cold, unafforded target stays out of the EIP-7928 block access list. For a create, the
/// account-creation state gas is charged when the destination is not already alive (existing,
/// non-empty), so a create at a pre-existing balance-only account pays nothing for the leaf
/// (execution-specs `created_target_alive`); nested creates are charged on the parent frame by
/// the CREATE opcode instead. A delegated recipient is still resolved (for free) so the frame
/// runs the delegate's code.
///
/// The frame's `gas_limit`/`reservoir` snapshot `tx_gas` after the charges. When a charge runs out
/// of gas the transaction stays valid but is included as an out-of-gas halt: the returned frame
/// is [`halted_initial_frame`], which [`execute_initial_frame`] halts without entering execution.
pub fn prepare_initial_frame<'a, T: EvmTypes>(
    host: &mut Evm<'a, T>,
    caller: Address,
    nonce: u64,
    to: TxKind,
    input: &Bytes,
    value: U256,
    tx_gas: &mut GasTracker,
) -> HandlerResult<InitialFrame<T>> {
    // A failed charge leaves `tx_gas` out of range, so the halted frame reports the budget the
    // phase started with.
    let budget = *tx_gas;
    let halted =
        |host: &Evm<'a, T>| halted_initial_frame(host, caller, nonce, to, input, value, &budget);
    let mut charged_state_gas = 0;
    let mut charged_state_gas_from_reservoir = 0;
    let message = match to {
        TxKind::Call(to) => {
            let (recipient_is_empty, mut code) = {
                let mut account = host.state.account(&to)?;
                // A nonexistent recipient reads as an empty account (EIP-161).
                let recipient_is_empty = account.get().is_none_or(AccountInfo::is_empty);
                (recipient_is_empty, account.load_code()?)
            };
            let mut code_address = to;
            if host.feature(EvmFeatures::EIP2780) && !value.is_zero() && recipient_is_empty {
                let new_account_state_gas =
                    T::state_gas_price(host, GasId::NewAccountState, StateGasSite::Account(to))?;
                let from_reservoir = new_account_state_gas.min(tx_gas.reservoir());
                if tx_gas.spend_state(new_account_state_gas).is_err() {
                    return Ok(halted(host));
                }
                charged_state_gas = new_account_state_gas;
                charged_state_gas_from_reservoir = from_reservoir;
            }
            // An empty recipient is never delegated, so the charge above and the resolution below
            // are mutually exclusive.
            if host.feature(EvmFeatures::EIP7702)
                && let Some(delegated_address) = code.eip7702_address()
            {
                if host.feature(EvmFeatures::EIP2780) {
                    // Delegation-target access, EIP-2929 warm/cold: charge the warm access first
                    // (covered → the target is loaded and enters the block access list), then the
                    // cold premium after the load. The load is skipped when the cold premium is
                    // unaffordable, keeping a cold, unafforded target out of the block access
                    // list.
                    let cold_additional = host.version().gas_params.cold_account_additional_cost();
                    if tx_gas.spend(u64::from(WARM_STORAGE_READ_COST)).is_err() {
                        return Ok(halted(host));
                    }
                    let skip_cold_load = tx_gas.remaining() < cold_additional;
                    let load =
                        match Host::load_account(host, &delegated_address, true, skip_cold_load) {
                            Ok(load) => load,
                            Err(HostError::Halt(_)) => return Ok(halted(host)),
                            Err(HostError::Execution(error)) => return Err(error.into()),
                        };
                    if load.is_cold && tx_gas.spend(cold_additional).is_err() {
                        return Ok(halted(host));
                    }
                    code = load.code;
                } else {
                    let mut account = host.state.account(&delegated_address)?;
                    account.warm();
                    code = account.load_code()?;
                }
                code_address = delegated_address;
            }
            MessageExt {
                kind: MessageKind::Call,
                depth: host.version().initial_call_depth,
                gas_limit: tx_gas.remaining(),
                reservoir: tx_gas.reservoir(),
                destination: to,
                call_target: to,
                caller,
                input: input.clone(),
                value,
                code,
                code_address,
                caller_is_static: false,
                salt: B256::ZERO,
                ext: T::MessageExt::default(),
                _non_exhaustive: (),
            }
        }
        TxKind::Create => {
            let destination = caller.create(nonce);
            if host.feature(EvmFeatures::EIP8037) {
                let target_alive =
                    host.state.account(&destination)?.get().is_some_and(|info| !info.is_empty());
                if !target_alive {
                    let create_state_gas = T::state_gas_price(
                        host,
                        GasId::CreateState,
                        StateGasSite::Account(destination),
                    )?;
                    let from_reservoir = create_state_gas.min(tx_gas.reservoir());
                    if tx_gas.spend_state(create_state_gas).is_err() {
                        return Ok(halted(host));
                    }
                    charged_state_gas = create_state_gas;
                    charged_state_gas_from_reservoir = from_reservoir;
                }
            }
            MessageExt {
                kind: MessageKind::Create,
                depth: host.version().initial_call_depth,
                gas_limit: tx_gas.remaining(),
                reservoir: tx_gas.reservoir(),
                destination,
                call_target: destination,
                caller,
                input: input.clone(),
                value,
                code: Bytecode::new_legacy(input.clone()),
                code_address: destination,
                caller_is_static: false,
                salt: B256::ZERO,
                ext: T::MessageExt::default(),
                _non_exhaustive: (),
            }
        }
    };
    debug_assert_eq!(message.depth, host.version().initial_call_depth);
    Ok(InitialFrame {
        message,
        charged_state_gas,
        charged_state_gas_from_reservoir,
        runtime_oog: false,
    })
}

/// Builds the first frame of a transaction whose runtime gas phase ran out of gas.
///
/// The message names the call or create the transaction would have run, with the `budget` the
/// runtime gas phase started with and no resolved bytecode, and it reads no account state: the
/// recipient of an unaffordable authorization charge stays out of the EIP-7928 block access list.
/// [`execute_initial_frame`] halts it with out-of-gas, reporting the frame to the inspector.
pub fn halted_initial_frame<T: EvmTypes>(
    host: &Evm<'_, T>,
    caller: Address,
    nonce: u64,
    to: TxKind,
    input: &Bytes,
    value: U256,
    budget: &GasTracker,
) -> InitialFrame<T> {
    let (kind, destination) = match to {
        TxKind::Call(to) => (MessageKind::Call, to),
        TxKind::Create => (MessageKind::Create, caller.create(nonce)),
    };
    let message = MessageExt {
        kind,
        depth: host.version().initial_call_depth,
        gas_limit: budget.remaining(),
        reservoir: budget.reservoir(),
        destination,
        call_target: destination,
        caller,
        input: input.clone(),
        value,
        code_address: destination,
        caller_is_static: false,
        salt: B256::ZERO,
        ..MessageExt::default()
    };
    InitialFrame {
        message,
        charged_state_gas: 0,
        charged_state_gas_from_reservoir: 0,
        runtime_oog: true,
    }
}

/// Settles the first frame's result into the transaction-level `tx_gas` and writes the settled
/// tracker back to the result for gas finalization.
///
/// All execution gas was forwarded to the frame, so it is first consumed on `tx_gas` and the
/// frame's settled gas merged back like any parent frame would
/// ([`GasTracker::merge_child_gas`]). When the frame did not create the account leaf whose state
/// gas the runtime gas phase charged upfront ([`InitialFrame::charged_state_gas`]), the charge
/// is refunded in LIFO order ([`GasTracker::refill_reservoir`]), exactly as the CALL/CREATE
/// opcodes refund their upfront state charges for failed children. Unlike an inner frame's
/// caller, the transaction ends here: an exceptional halt consumes all execution gas, including
/// the spilled portion the refill just credited back to `remaining`.
pub const fn settle_initial_frame_gas<E>(
    tx_gas: &mut GasTracker,
    result: &mut MessageResultExt<E>,
    charged_state_gas: u64,
) {
    tx_gas.spend_all();
    tx_gas.merge_child_gas(result.gas, result.stop);
    if charged_state_gas != 0 && !result.is_success() {
        tx_gas.refill_reservoir(charged_state_gas);
        if result.stop.is_halt() {
            tx_gas.spend_all();
        }
    }
    result.gas = *tx_gas;
}

/// [`settle_initial_frame_gas`] under the reservoir-only rule
/// ([`EvmFeatures::EIP8037_RESERVOIR_REFILLS`]).
///
/// The frame's settled gas is merged by [`GasTracker::merge_child_gas_into_reservoir`]. When the
/// frame did not create the account leaf the runtime gas phase charged for, the charge is given
/// back into the reservoir ([`GasTracker::refill_reservoir_only`]): all of it when the frame
/// reverted, and only `charged_state_gas_from_reservoir`, the part the reservoir paid, when it
/// halted. The part execution gas paid is then consumed with the halted frame's execution gas:
/// nothing of it returns to the sender, and it leaves the state gas spent, as a halted frame's own
/// state charges do.
pub const fn settle_initial_frame_gas_into_reservoir<E>(
    tx_gas: &mut GasTracker,
    result: &mut MessageResultExt<E>,
    charged_state_gas: u64,
    charged_state_gas_from_reservoir: u64,
) {
    tx_gas.spend_all();
    tx_gas.merge_child_gas_into_reservoir(result.gas, result.stop);
    if charged_state_gas != 0 && !result.is_success() {
        if result.stop.is_halt() {
            tx_gas.refill_reservoir_only(charged_state_gas_from_reservoir);
            let consumed = charged_state_gas - charged_state_gas_from_reservoir;
            tx_gas.add_state_gas_spent(-(consumed as i64));
        } else {
            tx_gas.refill_reservoir_only(charged_state_gas);
        }
    }
    result.gas = *tx_gas;
}

/// Executes the prepared first frame and settles its gas into the transaction-level tracker.
///
/// A frame whose runtime gas phase ran out of gas ([`InitialFrame::runtime_oog`]) is halted
/// without executing ([`Evm::execute_halted_message`]) and settled as [`runtime_oog_result`].
pub fn execute_initial_frame<T: EvmTypes>(
    host: &mut Evm<'_, T>,
    frame: InitialFrame<T>,
    tx_gas: &mut GasTracker,
    execution_gas_limit: u64,
    reservoir: u64,
) -> Result<MessageResult<T>, crate::ExecutionError> {
    let InitialFrame {
        mut message,
        charged_state_gas,
        charged_state_gas_from_reservoir,
        runtime_oog,
    } = frame;
    if runtime_oog {
        // The hooks see the frame burn the budget it was given; the transaction itself burns all
        // its execution gas and returns the reservoir, dropping the phase's partial charges.
        let halted = runtime_oog_result(message.gas_limit, message.reservoir);
        let mut result = host.execute_halted_message(&mut message, halted)?;
        result.gas = runtime_oog_result::<()>(execution_gas_limit, reservoir).gas;
        return Ok(result);
    }

    // Failed execution has already been rolled back to the message's own checkpoint inside
    // `execute_message`; the settle merges the frame gas into the transaction-level gas.
    let mut result = host.execute_message(&mut message)?;
    if host.feature(EvmFeatures::EIP8037_RESERVOIR_REFILLS) {
        settle_initial_frame_gas_into_reservoir(
            tx_gas,
            &mut result,
            charged_state_gas,
            charged_state_gas_from_reservoir,
        );
    } else {
        settle_initial_frame_gas(tx_gas, &mut result, charged_state_gas);
    }
    Ok(result)
}

/// Builds the result for a transaction whose EIP-2780 runtime gas phase ran out of gas
/// ([`prepare_initial_frame`] returned a [halted frame](halted_initial_frame), or the EIP-7702
/// authorization charges bailed).
///
/// The transaction is valid but cannot afford the state-dependent runtime charges: it is
/// included as an out-of-gas halt that consumes all execution gas and returns the reservoir,
/// without entering execution. The phase's partial charges are dropped by rebuilding the
/// pristine transaction-level gas from `execution_gas_limit` and `reservoir`.
pub fn runtime_oog_result<E: Default>(
    execution_gas_limit: u64,
    reservoir: u64,
) -> MessageResultExt<E> {
    MessageResultExt {
        stop: InstrStop::OutOfGas,
        gas: GasTracker::new_spent_with_reservoir(execution_gas_limit, reservoir),
        ..MessageResultExt::default()
    }
}

/// Applies the default Ethereum gas refund, sender reimbursement, and beneficiary reward rules.
pub fn default_settle_gas<'a, T: EvmTypes>(
    host: &mut Evm<'a, T>,
    settlement: GasSettlement<T>,
) -> HandlerResult<TxResult<T>> {
    let caller = settlement.caller;
    let gas_price = settlement.gas_price;
    let gas_limit = settlement.gas_limit;
    let result = finalize_gas(host, settlement)?;
    if host.feature(EvmFeatures::FEE_CHARGE) {
        let gas_used = result.tx_gas_used();
        let gas_remaining = gas_limit.saturating_sub(gas_used);
        let caller_refund = U256::from(gas_remaining) * gas_price;
        host.state.account(&caller)?.add_balance(caller_refund);
        // The base fee is burned from London on, independent of `BASE_FEE_CHECK`.
        let beneficiary_gas_price = if host.spec_id().enables(SpecId::LONDON) {
            gas_price.saturating_sub(host.block.basefee)
        } else {
            gas_price
        };
        let beneficiary = host.block.beneficiary;
        let beneficiary_reward = U256::from(gas_used) * beneficiary_gas_price;
        host.state.account(&beneficiary)?.add_balance(beneficiary_reward);
    }
    Ok(result)
}

/// Finalizes transaction gas accounting.
pub fn finalize_gas<'a, T: EvmTypes>(
    host: &mut Evm<'a, T>,
    settlement: GasSettlement<T>,
) -> HandlerResult<TxResult<T>> {
    let GasSettlement {
        caller: _,
        gas_price: _,
        gas_limit: tx_gas_limit,
        floor_gas,
        initial_state_gas,
        state_refund,
        result,
    } = settlement;

    let max_refund_quotient = host.version().gas_params.get(GasId::MaxRefundQuotient);
    let refunded = result.final_refund(tx_gas_limit, max_refund_quotient);
    // EIP-7623: when the calldata floor exceeds spent-minus-refund, `TxResult::tx_gas_used`
    // resolves to the floor. `total_gas_spent` stays pre-refund and pre-floor: block-level
    // execution gas (EIP-7778/EIP-8037) accumulates `tx_gas_used_before_refund` per
    // execution-specs, without the floor clamp.
    //
    // The per-authorization `state_refund` is EIP-7702 state gas returned on top of the settled
    // tracker's.
    let (total_gas_spent, state_gas_spent) =
        gas_spent_breakdown(tx_gas_limit, &result.gas, initial_state_gas);
    let state_gas_spent = state_gas_spent.saturating_sub(state_refund);
    Ok(TxResultExt {
        status: result.is_success(),
        total_gas_spent,
        state_gas_spent,
        refunded,
        floor_gas,
        stop: result.stop,
        output: result.output,
        created_address: result.created_address,
        ext: T::TxResultExt::default(),
        ..TxResultExt::default()
    })
}

/// Returns `(total_gas_spent, state_gas_spent)` for a settled transaction-level gas tracker.
///
/// `tx_gas_limit` is the execution gas limit plus the state-gas reservoir the transaction started
/// with. `total_gas_spent` is defined so that `TxResult::tx_gas_used` reproduces the finalized gas
/// used. `state_gas_spent` is the tracker's state gas plus the upfront `initial_state_gas`.
///
/// The settled tracker's state gas is self-consistent: a failed frame's state charges were rolled
/// back before it was merged, while unconditional pre-execution charges (the EIP-7702
/// authorizations, whose delegations survive an execution failure) remain. The upfront
/// `initial_state_gas` is likewise added unconditionally.
pub(crate) fn gas_spent_breakdown(
    tx_gas_limit: u64,
    gas: &GasTracker,
    initial_state_gas: u64,
) -> (u64, u64) {
    let total_gas_spent =
        tx_gas_limit.saturating_sub(gas.remaining()).saturating_sub(gas.reservoir());
    let state_gas_spent = gas.state_gas_spent().saturating_add_unsigned(initial_state_gas).max(0);
    (total_gas_spent, state_gas_spent as u64)
}

/// Returns the account and storage-key counts in an access list.
pub fn access_list_counts(access_list: &AccessList) -> (u64, u64) {
    (access_list.len() as u64, access_list.storage_keys_count() as u64)
}

/// Calculates intrinsic transaction gas and the calldata floor gas, returned as
/// `(intrinsic_gas, floor_gas)`. The floor is zero without EIP-7623.
///
/// `caller`/`value` feed the EIP-2780 decomposed model (which branches on
/// self-transfer and whether `tx.value` is zero); the legacy model ignores them.
/// Under EIP-2780 the floor is also anchored on that decomposed base
/// (`TX_BASE` + `to`-based + `value`-based, ethereum/EIPs#11836) instead of the
/// flat `TxFloorCostBase`, so it never undercuts the transaction's own
/// intrinsic base.
pub fn intrinsic_and_floor_gas(
    version: &Version,
    caller: Address,
    to: TxKind,
    input: &Bytes,
    access_list_accounts: u64,
    access_list_storage_keys: u64,
    value: U256,
) -> (u64, u64) {
    let params = &version.gas_params;
    let (tokens, floor_tokens) = params.tx_calldata_tokens(input);
    let mut gas = tokens * params.get(GasId::TxTokenCost);
    gas += access_list_accounts * params.get(GasId::TxAccessListAddressCost);
    gas += access_list_storage_keys * params.get(GasId::TxAccessListStorageKeyCost);

    // Base + `to`-based + `value`-based charges.
    let is_create = to.is_create();
    let eip2780_base = version.feature(EvmFeatures::EIP2780).then(|| {
        // EIP-2780: decomposed model replacing the legacy 21,000 base.
        let is_self_transfer = matches!(to, TxKind::Call(to) if to == caller);
        eip2780_base_to_value_gas(version, is_create, is_self_transfer, value)
    });
    if let Some(base) = eip2780_base {
        gas += base;
    } else {
        gas += params.get(GasId::TxBaseStipend);
        if is_create && version.feature(EvmFeatures::EIP2) {
            gas += params.get(GasId::TxCreateCost);
        }
    }
    if is_create && version.feature(EvmFeatures::EIP3860) {
        gas += params.get(GasId::TxInitcodeCost) * num_words(input.len()) as u64;
    }

    let floor_cost_per_token = params.get(GasId::TxFloorCostPerToken);
    if !version.feature(EvmFeatures::EIP7623) || floor_cost_per_token == 0 {
        return (gas, 0);
    }

    let floor_base = eip2780_base.unwrap_or_else(|| params.get(GasId::TxFloorCostBase));
    let floor_gas = params.tx_floor_cost_with_base(
        floor_base,
        floor_tokens,
        access_list_accounts,
        access_list_storage_keys,
    );
    (gas, floor_gas)
}

/// EIP-2780: sum of the sender base, `tx.to`-based, and `tx.value`-based
/// execution-gas charges. Excludes calldata, access list, authorizations, and
/// initcode pieces which are added by the caller.
///
/// Per execution-specs, a self-transfer (`tx.to == sender`) pays neither the
/// `to`- nor `value`-based charge — only the base. Precompile recipients are
/// charged the same as any other account (the precompile carve-out from the
/// draft is not implemented).
fn eip2780_base_to_value_gas(
    version: &Version,
    is_create: bool,
    is_self_transfer: bool,
    value: U256,
) -> u64 {
    let params = &version.gas_params;
    let mut gas = params.get(GasId::TxBaseStipend);
    if is_create {
        // Since glamsterdam devnet-8, creates pay no value-based charge.
        gas += params.get(GasId::TxCreateAccessCost);
    } else if !is_self_transfer {
        gas += params.get(GasId::WarmStorageReadCost) + params.cold_account_additional_cost();
        if !value.is_zero() {
            gas += params.get(GasId::TxValueCost);
        }
    }
    gas
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BaseEvmTypes, ExecutionConfig, Precompiles,
        constants::MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM,
        env::BlockEnvExt,
        evm::{InMemoryDB, handler::TxHandlerHooks},
        interpreter::{Host, InstrStop, op},
        registry::TxRegistry,
    };
    use alloc::{format, string::ToString, vec};
    use alloy_consensus::{TxEip2930, transaction::Recovered};
    use alloy_eips::eip2930::AccessList;

    #[rstest::rstest]
    fn adjusted_floor_gas_controls_validation_and_settlement(
        #[values(31_049, 31_050)] gas_limit: u64,
    ) {
        struct CalldataSurcharge;

        impl TxHandlerHooks<BaseEvmTypes> for CalldataSurcharge {
            fn adjust_intrinsic_gas(
                _host: &mut Evm<'_, BaseEvmTypes>,
                _envelope: &TxEnvelope,
                intrinsic: &mut u64,
                initial_state_gas: &mut u64,
                floor_gas: &mut u64,
            ) -> HandlerResult<()> {
                assert_eq!(*intrinsic, 21_020);
                assert_eq!(*initial_state_gas, 0);
                assert_eq!(*floor_gas, 21_050);
                *intrinsic += 10_000;
                *floor_gas += 10_000;
                Ok(())
            }
        }

        let caller = Address::with_last_byte(0xaa);
        let tx = Recovered::new_unchecked(
            TxEnvelope::Legacy(TxLegacy {
                gas_limit,
                to: TxKind::Call(Address::with_last_byte(0xbb)),
                input: Bytes::from_static(&[0, 1]),
                ..TxLegacy::default()
            }),
            caller,
        );
        let registry = TxRegistry::new().with_handler(
            0,
            TxEnvelope::as_legacy,
            handler(
                legacy::prepare_with_hooks::<BaseEvmTypes, CalldataSurcharge>,
                legacy::execute_prepared::<BaseEvmTypes, CalldataSurcharge>,
            ),
        );
        let mut evm = Evm::<BaseEvmTypes>::new(
            SpecId::PRAGUE,
            BlockEnvExt::default(),
            registry,
            InMemoryDB::default(),
            Precompiles::base(SpecId::PRAGUE),
        );

        let validation = evm.validate_tx(&tx);
        let result = evm.call_tx(&tx);
        assert_eq!(validation, result.as_ref().map(|_| ()).map_err(Clone::clone));
        if gas_limit < 31_050 {
            assert_eq!(
                result,
                Err(HandlerError::GasLimitBelowFloor { required: 31_050, got: gas_limit })
            );
        } else {
            let result = result.unwrap();
            assert!(result.is_success());
            assert_eq!(result.total_gas_spent, 31_020);
            assert_eq!(result.floor_gas, 31_050);
            assert_eq!(result.tx_gas_used(), 31_050);
        }
    }

    #[test]
    fn intrinsic_gas_charges_shanghai_create_initcode_words() {
        let input = Bytes::from(vec![1; 74]);

        let sender = Address::with_last_byte(0xaa);
        let intrinsic = |version: &Version| {
            intrinsic_and_floor_gas(version, sender, TxKind::Create, &input, 0, 0, U256::ZERO).0
        };
        assert_eq!(intrinsic(Version::base(SpecId::LONDON)), 21_000 + 32_000 + 74 * 16);
        assert_eq!(intrinsic(Version::base(SpecId::SHANGHAI)), 21_000 + 32_000 + 74 * 16 + 3 * 2);
    }

    #[test]
    fn intrinsic_gas_charges_access_list_items() {
        let input = Bytes::new();
        let sender = Address::with_last_byte(0xaa);
        let to = TxKind::Call(Address::ZERO);
        let intrinsic = |version: &Version, accounts, keys| {
            intrinsic_and_floor_gas(version, sender, to, &input, accounts, keys, U256::ZERO).0
        };

        assert_eq!(intrinsic(Version::base(SpecId::BERLIN), 2, 3), 21_000 + 2 * 2400 + 3 * 1900);
        assert_eq!(
            intrinsic(Version::base(SpecId::AMSTERDAM), 1, 1),
            // EIP-2780 replaces the 21,000 base with TX_BASE (12,000) +
            // COLD_ACCOUNT_ACCESS (3,000) for the zero-value call recipient.
            // EIP-8038 sets the per-item access-list base to the cold-minus-warm
            // premium: 2,900 per address and 2,000 per storage key.
            (12_000 + 3000) + (2900 + 20 * 64) + (2000 + 32 * 64)
        );
    }

    #[test]
    fn intrinsic_gas_reads_calldata_and_base_costs_from_gas_params() {
        let input = Bytes::from_static(&[0, 1, 2]);
        let sender = Address::with_last_byte(0xaa);
        let mut version = Version::new(SpecId::PRAGUE);
        version.gas_params.set(GasId::TxTokenCost, 3);
        version.gas_params.set(GasId::TxTokenNonZeroByteMultiplier, 5);
        version.gas_params.set(GasId::TxBaseStipend, 10_000);

        let (intrinsic, _) = intrinsic_and_floor_gas(
            &version,
            sender,
            TxKind::Call(Address::ZERO),
            &input,
            0,
            0,
            U256::ZERO,
        );
        assert_eq!(intrinsic, 10_000 + (1 + 2 * 5) * 3);
    }

    #[test]
    fn eip2930_rejects_gas_below_intrinsic() {
        let caller = Address::with_last_byte(0xaa);
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &caller,
            AccountInfo::default().with_balance(U256::from(1_000_000_000u64)),
        );
        let tx = Recovered::new_unchecked(
            TxEnvelope::Eip2930(TxEip2930 {
                chain_id: 1,
                nonce: 0,
                gas_price: 1,
                gas_limit: 20_999,
                to: TxKind::Call(Address::with_last_byte(0xbb)),
                value: U256::ZERO,
                input: Bytes::new(),
                access_list: AccessList::default(),
            }),
            caller,
        );
        let mut evm = Evm::<BaseEvmTypes>::new(
            SpecId::BERLIN,
            BlockEnvExt::default(),
            ethereum_tx_registry(SpecId::BERLIN),
            database,
            Precompiles::base(SpecId::BERLIN),
        );

        assert_eq!(
            evm.transact(&tx).map(|executed| executed.discard()),
            Err(HandlerError::IntrinsicGasTooLow { required: 21_000, got: 20_999 })
        );
    }

    #[test]
    fn gas_limit_below_floor_is_not_an_intrinsic_gas_error() {
        assert_eq!(
            validate_intrinsic_gas(20_999, 21_000, 0),
            Err(HandlerError::IntrinsicGasTooLow { required: 21_000, got: 20_999 })
        );
        assert_eq!(
            validate_floor_gas(21_009, 21_010),
            Err(HandlerError::GasLimitBelowFloor { required: 21_010, got: 21_009 })
        );
        assert_eq!(validate_floor_gas(21_010, 21_010), Ok(()));
    }

    #[test]
    fn floor_gas_charges_prague_calldata_tokens() {
        let input = Bytes::from_static(&[0, 1, 2]);
        let sender = Address::with_last_byte(0xaa);
        let to = TxKind::Call(Address::ZERO);
        let mut prague_without_eip7623 = Version::new(SpecId::PRAGUE);
        prague_without_eip7623.features.remove(EvmFeatures::EIP7623);
        let floor = |version: &Version| {
            intrinsic_and_floor_gas(version, sender, to, &input, 0, 0, U256::ZERO).1
        };

        assert_eq!(floor(Version::base(SpecId::SHANGHAI)), 0);
        assert_eq!(floor(Version::base(SpecId::PRAGUE)), 21_000 + 9 * 10);
        assert_eq!(floor(&prague_without_eip7623), 0);
    }

    #[test]
    fn floor_gas_charges_amsterdam_access_list_tokens() {
        let input = Bytes::from(vec![1; 1000]);
        let sender = Address::with_last_byte(0xaa);
        // A plain value-less call to a different address: EIP-2780
        // (ethereum/EIPs#11836) anchors the floor base on the decomposed
        // intrinsic base `TX_BASE + COLD_ACCOUNT_ACCESS` (12,000 + 3,000)
        // instead of the flat `TxFloorCostBase`.
        let to = TxKind::Call(Address::ZERO);
        let floor = |version: &Version, input: &Bytes, accounts, keys| {
            intrinsic_and_floor_gas(version, sender, to, input, accounts, keys, U256::ZERO).1
        };

        assert_eq!(
            floor(Version::base(SpecId::AMSTERDAM), &input, 1, 1),
            15_000 + (1000 * 4 + 80 + 128) * 16
        );

        // EIP-7976: amsterdam weights zero calldata bytes the same as non-zero
        // bytes in the floor (4 tokens each), unlike EIP-7623 (zero = 1 token).
        let zero_input = Bytes::from(vec![0; 1000]);
        assert_eq!(
            floor(Version::base(SpecId::AMSTERDAM), &zero_input, 1, 1),
            15_000 + (1000 * 4 + 80 + 128) * 16
        );
        // Prague keeps the EIP-7623 split: zero bytes count as one token each.
        assert_eq!(floor(Version::base(SpecId::PRAGUE), &zero_input, 0, 0), 21_000 + 1000 * 10);
    }

    #[test]
    fn features_gate_transaction_validation() {
        let mut london = Version::new(SpecId::LONDON);
        assert_eq!(
            validate_gas_price(&london, U256::ZERO, U256::ONE),
            Err(HandlerError::FeeCapLessThanBaseFee {
                max_fee_per_gas: U256::ZERO,
                base_fee: U256::ONE,
            })
        );
        london.features.remove(EvmFeatures::BASE_FEE_CHECK);
        assert_eq!(validate_gas_price(&london, U256::ZERO, U256::ONE), Ok(()));

        // A configured base fee is checked before London too.
        assert_eq!(
            validate_gas_price(&Version::new(SpecId::BERLIN), U256::ZERO, U256::ONE),
            Err(HandlerError::FeeCapLessThanBaseFee {
                max_fee_per_gas: U256::ZERO,
                base_fee: U256::ONE,
            })
        );

        let mut prague = Version::new(SpecId::PRAGUE);
        assert_eq!(
            validate_priority_fee(&prague, U256::ONE, U256::from(2)),
            Err(HandlerError::PriorityFeeGreaterThanMaxFee)
        );
        prague.features.remove(EvmFeatures::PRIORITY_FEE_CHECK);
        assert_eq!(validate_priority_fee(&prague, U256::ONE, U256::from(2)), Ok(()));

        assert_eq!(
            validate_block_gas_limit(&prague, 2, U256::ONE),
            Err(HandlerError::GasLimitMoreThanBlock { gas_limit: 2, block_gas_limit: U256::ONE })
        );
        prague.features.remove(EvmFeatures::BLOCK_GAS_LIMIT_CHECK);
        assert_eq!(validate_block_gas_limit(&prague, 2, U256::ONE), Ok(()));

        let mut version = Version::new(SpecId::OSAKA);
        version.chain_id = 10;
        assert_eq!(validate_chain_id(&version, Some(10), false), Ok(()));
        assert_eq!(
            validate_chain_id(&version, Some(1), false),
            Err(HandlerError::InvalidChainId { expected: 10, got: 1 })
        );
        assert_eq!(validate_chain_id(&version, None, false), Err(HandlerError::MissingChainId));
        assert_eq!(validate_chain_id(&version, None, true), Ok(()));
        version.features.remove(EvmFeatures::TX_CHAIN_ID_CHECK);
        assert_eq!(validate_chain_id(&version, Some(1), false), Ok(()));
    }

    #[rstest::rstest]
    #[case::berlin(SpecId::BERLIN, true, 15)]
    #[case::london(SpecId::LONDON, true, 5)]
    #[case::london_without_base_fee_check(SpecId::LONDON, false, 5)]
    fn base_fee_burn_depends_on_spec(
        #[case] spec: SpecId,
        #[case] base_fee_check: bool,
        #[case] beneficiary_gas_price: u64,
    ) {
        let caller = Address::with_last_byte(0xaa);
        let beneficiary = Address::with_last_byte(0xcc);
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &caller,
            AccountInfo::default().with_balance(U256::from(1_000_000_000)),
        );
        let mut version = Version::new(spec);
        version.features.set(EvmFeatures::BASE_FEE_CHECK, base_fee_check);
        let block = BlockEnvExt { basefee: U256::from(10), beneficiary, ..BlockEnvExt::default() };
        let mut evm = Evm::<BaseEvmTypes>::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(spec, version),
            spec,
            block,
            ethereum_tx_registry(spec),
            database,
            Precompiles::base(spec),
        );
        let tx = Recovered::new_unchecked(
            TxEnvelope::Legacy(TxLegacy {
                gas_price: 15,
                gas_limit: 21_000,
                to: TxKind::Call(Address::with_last_byte(0xbb)),
                ..TxLegacy::default()
            }),
            caller,
        );

        assert!(evm.transact(&tx).unwrap().commit().is_success());
        let reward = evm.read_account_info(&beneficiary).unwrap().unwrap().balance;
        assert_eq!(reward, U256::from(21_000 * beneficiary_gas_price));
    }

    /// The transaction-level state charges are priced by the type family at their location: a
    /// value transfer's new recipient and a creation's account. At three times the schedule's
    /// prices the transaction's tracker spends three times the state gas; a price the family
    /// cannot give aborts the transaction.
    #[test]
    fn initial_frame_state_charges_take_the_family_price() {
        use crate::{
            test_utils::{PricedTypes, Prices},
            version::StateGasSite::Account,
        };
        let caller = Address::with_last_byte(0xaa);
        let recipient = Address::with_last_byte(0xbb);
        let evm = |prices| {
            Evm::<PricedTypes>::new_with_ext(
                SpecId::AMSTERDAM,
                BlockEnvExt::default(),
                TxRegistry::new(),
                InMemoryDB::default(),
                Precompiles::base(SpecId::AMSTERDAM),
                prices,
            )
        };
        for (to, value, site) in [
            (TxKind::Call(recipient), U256::from(1), (GasId::NewAccountState, Account(recipient))),
            (TxKind::Create, U256::ZERO, (GasId::CreateState, Account(caller.create(0)))),
        ] {
            let mut spent = vec![];
            for multiplier in [1, 3] {
                let mut evm = evm(Prices { multiplier, ..Prices::default() });
                let mut tx_gas =
                    GasTracker::new_with_execution_gas_and_reservoir(1_000_000, 1_000_000);
                let frame = prepare_initial_frame(
                    &mut evm,
                    caller,
                    0,
                    to,
                    &Bytes::new(),
                    value,
                    &mut tx_gas,
                )
                .unwrap();
                assert_eq!(evm.ext().seen, [site]);
                assert_eq!(frame.charged_state_gas as i64, tx_gas.state_gas_spent());
                spent.push(tx_gas.state_gas_spent());
            }
            assert!(spent[0] > 0);
            assert_eq!(spent[1], 3 * spent[0]);
        }
        let mut evm = evm(Prices { fail: Some(GasId::CreateState), ..Prices::default() });
        let mut tx_gas = GasTracker::new_with_execution_gas_and_reservoir(1_000_000, 1_000_000);
        let result = prepare_initial_frame(
            &mut evm,
            caller,
            0,
            TxKind::Create,
            &Bytes::new(),
            U256::ZERO,
            &mut tx_gas,
        );
        assert!(result.is_err(), "the hook's error aborts the transaction");
    }

    #[test]
    fn insufficient_funds_reports_cost_and_balance() {
        let caller = Address::with_last_byte(0xaa);
        let mut database = InMemoryDB::default();
        database.insert_account_info(&caller, AccountInfo::default().with_balance(U256::from(10)));
        let mut evm = Evm::<BaseEvmTypes>::new(
            SpecId::OSAKA,
            BlockEnvExt::default(),
            TxRegistry::new(),
            database,
            Precompiles::base(SpecId::OSAKA),
        );

        let error = validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::from(100));
        assert_eq!(
            error,
            Err(HandlerError::InsufficientFunds { fee: U256::from(100), balance: U256::from(10) })
        );
        assert_eq!(error.unwrap_err().to_string(), "lack of funds (10) for max fee (100)");
    }

    #[test]
    fn balance_top_up_can_be_disabled_independently() {
        let caller = Address::with_last_byte(0xaa);
        let mut version = Version::new(SpecId::OSAKA);
        version.features.remove(EvmFeatures::BALANCE_CHECK);
        version.features.remove(EvmFeatures::BALANCE_TOP_UP);
        let mut evm = Evm::<BaseEvmTypes>::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
            SpecId::OSAKA,
            BlockEnvExt::default(),
            TxRegistry::new(),
            InMemoryDB::default(),
            Precompiles::base(SpecId::OSAKA),
        );

        assert!(validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::from(100)).is_ok());
        let sender = evm.read_account_info(&caller).unwrap().unwrap();
        assert_eq!((sender.balance, sender.nonce), (U256::ZERO, 1));
    }

    #[test]
    fn features_gate_sender_validation() {
        let caller = Address::with_last_byte(0xaa);
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &caller,
            AccountInfo::default()
                .with_nonce(7)
                .with_code(Bytecode::new_legacy(Bytes::from_static(&[op::STOP]))),
        );

        let mut version = Version::new(SpecId::OSAKA);
        version.features.remove(EvmFeatures::EIP3607);
        version.features.remove(EvmFeatures::NONCE_CHECK);
        version.features.remove(EvmFeatures::BALANCE_CHECK);
        let mut evm = Evm::<BaseEvmTypes>::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
            SpecId::OSAKA,
            BlockEnvExt::default(),
            TxRegistry::new(),
            database,
            Precompiles::base(SpecId::OSAKA),
        );

        assert!(validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::from(100)).is_ok());
        assert_eq!(evm.read_account_info(&caller).unwrap().unwrap().balance, U256::from(100));
    }

    #[test]
    fn charge_upfront_saturates_insufficient_balance() {
        let caller = Address::with_last_byte(0xaa);
        let mut database = InMemoryDB::default();
        database.insert_account_info(&caller, AccountInfo::default().with_balance(U256::from(10)));

        let mut version = Version::new(SpecId::OSAKA);
        version.features.remove(EvmFeatures::BALANCE_CHECK);
        version.features.remove(EvmFeatures::BALANCE_TOP_UP);
        let mut evm = Evm::<BaseEvmTypes>::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
            SpecId::OSAKA,
            BlockEnvExt::default(),
            TxRegistry::new(),
            database,
            Precompiles::base(SpecId::OSAKA),
        );

        assert!(validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::from(100)).is_ok());
        charge_upfront(&mut evm, caller, U256::from(100)).unwrap();
        assert_eq!(evm.read_account_info(&caller).unwrap().unwrap().balance, U256::ZERO);
    }

    #[test]
    fn initial_delegated_call_uses_delegated_code_address() {
        let caller = Address::with_last_byte(0xaa);
        let target = Address::with_last_byte(0x55);
        let delegated = Address::with_last_byte(0x33);
        let delegated_code = Bytecode::new_legacy(Bytes::from_static(&[
            op::PUSH1,
            0x2a,
            op::PUSH0,
            op::MSTORE,
            op::PUSH1,
            0x20,
            op::PUSH0,
            op::RETURN,
        ]));
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &target,
            AccountInfo::default().with_code(Bytecode::new_eip7702(delegated)),
        );
        database.insert_account_info(&delegated, AccountInfo::default().with_code(delegated_code));
        let mut evm = Evm::<BaseEvmTypes>::new(
            SpecId::PRAGUE,
            BlockEnvExt::default(),
            TxRegistry::new(),
            database,
            Precompiles::base(SpecId::PRAGUE),
        );

        let mut tx_gas = GasTracker::new_with_execution_gas_and_reservoir(100_000, 0);
        let InitialFrame { mut message, charged_state_gas, .. } = prepare_initial_frame(
            &mut evm,
            caller,
            0,
            TxKind::Call(target),
            &Bytes::new(),
            U256::ZERO,
            &mut tx_gas,
        )
        .unwrap();
        assert_eq!(message.destination, target);
        assert_eq!(message.code_address, delegated);
        assert_eq!(charged_state_gas, 0);

        let result = Host::execute_message(&mut evm, &mut message).unwrap();

        assert_eq!(result.stop, InstrStop::Return);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 0x2a);
    }

    #[test]
    fn amsterdam_allows_total_gas_above_osaka_cap_when_execution_gas_fits() {
        let osaka = Version::base(SpecId::OSAKA);
        let amsterdam = Version::base(SpecId::AMSTERDAM);
        let tx_gas_limit = osaka.tx_gas_limit_cap + 1;
        let intrinsic = 21_000;
        let floor_gas = 21_000;

        assert_eq!(
            validate_tx_gas_limit_cap(osaka, tx_gas_limit),
            Err(HandlerError::TxGasLimitGreaterThanCap {
                gas_limit: tx_gas_limit,
                cap: osaka.tx_gas_limit_cap
            })
        );
        assert_eq!(validate_tx_gas_limit_cap(amsterdam, tx_gas_limit), Ok(()));
        assert_eq!(validate_tx_gas_limit_cap(amsterdam, MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM), Ok(()));
        assert_eq!(
            validate_tx_gas_limit_cap(amsterdam, MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM + 1),
            Err(HandlerError::TxGasLimitGreaterThanCap {
                gas_limit: MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM + 1,
                cap: MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM
            })
        );
        assert_eq!(
            validate_execution_gas_limit_cap(amsterdam, tx_gas_limit, intrinsic, floor_gas),
            Ok(())
        );
        assert_eq!(
            validate_execution_gas_limit_cap(
                amsterdam,
                tx_gas_limit,
                amsterdam.tx_gas_limit_cap + 1,
                floor_gas,
            ),
            Err(HandlerError::IntrinsicGasGreaterThanCap {
                required: amsterdam.tx_gas_limit_cap + 1,
                cap: amsterdam.tx_gas_limit_cap
            })
        );

        let mut amsterdam_without_eip8037 = Version::new(SpecId::AMSTERDAM);
        amsterdam_without_eip8037.features.remove(EvmFeatures::EIP8037);
        assert_eq!(
            validate_tx_gas_limit_cap(&amsterdam_without_eip8037, tx_gas_limit),
            Err(HandlerError::TxGasLimitGreaterThanCap {
                gas_limit: tx_gas_limit,
                cap: amsterdam_without_eip8037.tx_gas_limit_cap,
            })
        );
    }

    #[rstest::rstest]
    fn amsterdam_handler_rejects_gas_limit_above_total_cap(
        #[values(MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM, MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM + 1)]
        gas_limit: u64,
    ) {
        let mut evm = Evm::<BaseEvmTypes>::new(
            SpecId::AMSTERDAM,
            BlockEnvExt::default(),
            ethereum_tx_registry(SpecId::AMSTERDAM),
            InMemoryDB::default(),
            Precompiles::base(SpecId::AMSTERDAM),
        );
        let tx = Recovered::new_unchecked(
            TxEnvelope::Eip2930(TxEip2930 {
                chain_id: 1,
                gas_limit,
                to: TxKind::Call(Address::with_last_byte(0xbb)),
                ..Default::default()
            }),
            Address::with_last_byte(0xaa),
        );

        let expected = if gas_limit > MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM {
            Err(HandlerError::TxGasLimitGreaterThanCap {
                gas_limit,
                cap: MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM,
            })
        } else {
            Ok(())
        };
        assert_eq!(evm.validate_tx(&tx), expected);
    }

    #[rstest::rstest]
    #[case::call_zero_value(TxKind::Call(Address::ZERO), U256::ZERO, 15_000, 12_700)]
    #[case::call_with_value(TxKind::Call(Address::ZERO), U256::ONE, 21_000, 18_700)]
    #[case::self_transfer_zero_value(
        TxKind::Call(Address::with_last_byte(0xaa)),
        U256::ZERO,
        12_000,
        10_000
    )]
    #[case::self_transfer_with_value(
        TxKind::Call(Address::with_last_byte(0xaa)),
        U256::ONE,
        12_000,
        10_000
    )]
    #[case::create_zero_value(TxKind::Create, U256::ZERO, 24_000, 22_000)]
    #[case::create_with_value(TxKind::Create, U256::ONE, 24_000, 22_000)]
    fn eip2780_intrinsic_and_floor_gas_read_base_costs_from_gas_params(
        #[case] to: TxKind,
        #[case] value: U256,
        #[case] default_base: u64,
        #[case] custom_base: u64,
        #[values(false, true)] custom_params: bool,
    ) {
        let sender = Address::with_last_byte(0xaa);
        let mut version = Version::new(SpecId::AMSTERDAM);
        if custom_params {
            version.gas_params.set(GasId::TxBaseStipend, 10_000);
            version.gas_params.set(GasId::WarmStorageReadCost, 200);
            version.gas_params.set(GasId::ColdAccountAdditionalCost, 2500);
        }
        let base = if custom_params { custom_base } else { default_base };

        for input in [Bytes::new(), Bytes::from_static(&[0, 1])] {
            let calldata_gas = if input.is_empty() { 0 } else { 20 };
            let floor_calldata_gas = if input.is_empty() { 0 } else { 128 };
            let initcode_gas = if to.is_create() && !input.is_empty() { 2 } else { 0 };
            let (intrinsic, floor) =
                intrinsic_and_floor_gas(&version, sender, to, &input, 0, 0, value);
            assert_eq!(intrinsic, base + calldata_gas + initcode_gas);
            assert_eq!(floor, base + floor_calldata_gas);
        }
    }

    #[rstest::rstest]
    fn underfunded_top_level_value_depends_on_balance_check(
        #[values(false, true)] balance_check: bool,
        #[values(false, true)] fee_charge: bool,
    ) {
        let caller = Address::with_last_byte(0xaa);
        let recipient = Address::with_last_byte(0xbb);
        for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
            for to in [TxKind::Create, TxKind::Call(recipient)] {
                for value in [0, 1, 2] {
                    for input in [
                        Bytes::from_static(&[op::STOP]),
                        Bytes::from_static(&[op::PUSH0, op::PUSH0, op::REVERT]),
                    ] {
                        for tx_type in 0..=2 {
                            let mut version = Version::new(spec);
                            version.features.remove(EvmFeatures::BALANCE_TOP_UP);
                            version.features.set(EvmFeatures::BALANCE_CHECK, balance_check);
                            version.features.set(EvmFeatures::FEE_CHARGE, fee_charge);
                            let mut database = InMemoryDB::default();
                            database.insert_account_info(
                                &caller,
                                AccountInfo::default().with_nonce(10).with_balance(U256::ONE),
                            );
                            database.insert_account_info(
                                &recipient,
                                AccountInfo::default()
                                    .with_code(Bytecode::new_legacy(input.clone())),
                            );
                            let tx = match tx_type {
                                0 => TxEnvelope::Legacy(TxLegacy {
                                    nonce: 10,
                                    gas_limit: 500_000,
                                    to,
                                    value: U256::from(value),
                                    input: input.clone(),
                                    ..Default::default()
                                }),
                                1 => TxEnvelope::Eip2930(TxEip2930 {
                                    chain_id: version.chain_id,
                                    nonce: 10,
                                    gas_limit: 500_000,
                                    to,
                                    value: U256::from(value),
                                    input: input.clone(),
                                    ..Default::default()
                                }),
                                _ => TxEnvelope::Eip1559(TxEip1559 {
                                    chain_id: version.chain_id,
                                    nonce: 10,
                                    gas_limit: 500_000,
                                    to,
                                    value: U256::from(value),
                                    input: input.clone(),
                                    ..Default::default()
                                }),
                            };
                            let mut evm = Evm::<BaseEvmTypes>::new_with_execution_config(
                                ExecutionConfig::for_spec_and_version(spec, version),
                                spec,
                                BlockEnvExt {
                                    gas_limit: U256::from(10_000_000),
                                    ..Default::default()
                                },
                                ethereum_tx_registry(spec),
                                database,
                                Precompiles::base(spec),
                            );
                            let tx = Recovered::new_unchecked(tx, caller);
                            let case = format!("{spec:?} {to:?} value={value} type={tx_type}");
                            let caller_before = evm.read_account_info(&caller).unwrap();
                            let recipient_before = evm.read_account_info(&recipient).unwrap();
                            if balance_check && value == 2 {
                                assert_eq!(
                                    evm.call_tx(&tx),
                                    Err(HandlerError::InsufficientFunds {
                                        fee: U256::from(2),
                                        balance: U256::ONE
                                    }),
                                    "{case}"
                                );
                                assert_eq!(
                                    evm.read_account_info(&caller).unwrap(),
                                    caller_before,
                                    "{case}"
                                );
                                assert_eq!(
                                    evm.read_account_info(&recipient).unwrap(),
                                    recipient_before,
                                    "{case}"
                                );
                                continue;
                            }
                            let result = evm.transact(&tx).unwrap().commit();
                            if value == 2 {
                                assert_eq!(result.stop, InstrStop::OutOfFunds, "{case}");
                            } else {
                                assert_eq!(result.is_success(), input[0] == op::STOP, "{case}");
                            }
                            let nonce = evm.read_account_info(&caller).unwrap().unwrap().nonce;
                            assert_eq!(nonce, 11, "{case}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn tx_total_gas_cap_default_rejects_two_pow_32() {
        let amsterdam = Version::base(SpecId::AMSTERDAM);
        let gas_limit = 1u64 << 32;

        assert!(amsterdam.feature(EvmFeatures::EIP8037));
        assert_eq!(
            validate_tx_gas_limit_cap(amsterdam, gas_limit),
            Err(HandlerError::TxGasLimitGreaterThanCap {
                gas_limit,
                cap: MAX_TX_TOTAL_GAS_LIMIT_AMSTERDAM,
            })
        );
    }

    #[test]
    fn tx_total_gas_cap_disabled_allows_two_pow_32() {
        let mut amsterdam = Version::new(SpecId::AMSTERDAM);
        amsterdam.tx_total_gas_cap = u64::MAX;
        let gas_limit = 1u64 << 32;

        assert!(amsterdam.feature(EvmFeatures::EIP8037));
        assert_eq!(validate_tx_gas_limit_cap(&amsterdam, gas_limit), Ok(()));
        assert_eq!(validate_tx_gas_limit_cap(&amsterdam, u64::MAX), Ok(()));
    }

    #[test]
    fn tx_total_gas_cap_custom_value_is_enforced() {
        let mut amsterdam = Version::new(SpecId::AMSTERDAM);
        let cap = 50_000_000;
        amsterdam.tx_total_gas_cap = cap;

        assert!(amsterdam.feature(EvmFeatures::EIP8037));
        assert_eq!(validate_tx_gas_limit_cap(&amsterdam, cap), Ok(()));
        assert_eq!(
            validate_tx_gas_limit_cap(&amsterdam, cap + 1),
            Err(HandlerError::TxGasLimitGreaterThanCap { gas_limit: cap + 1, cap })
        );
    }

    /// Every `Transaction` accessor of the envelope reads its transaction, for each kind.
    #[test]
    fn tx_envelope_accessors_read_the_transaction() {
        use alloy_consensus::{TxEip1559, TxEip4844, TxEip7702};
        use alloy_eips::{
            eip2930::AccessListItem,
            eip7702::{Authorization, SignedAuthorization},
        };
        let to = Address::with_last_byte(0xbb);
        let list = AccessList(vec![AccessListItem {
            address: to,
            storage_keys: vec![B256::repeat_byte(2)],
        }]);
        let input = Bytes::from_static(&[1, 2, 3]);
        let value = U256::from(11);
        let auth = SignedAuthorization::new_unchecked(
            Authorization { chain_id: U256::from(7), address: to, nonce: 1 },
            0,
            U256::from(1),
            U256::from(1),
        );
        let create = TxLegacy {
            chain_id: Some(7),
            nonce: 3,
            gas_price: 9,
            gas_limit: 21_007,
            to: TxKind::Create,
            value,
            input: input.clone(),
        };
        let envelopes = [
            TxEnvelope::Legacy(create.clone()),
            TxEnvelope::Legacy(TxLegacy { to: TxKind::Call(to), ..create }),
            TxEnvelope::Eip2930(TxEip2930 {
                chain_id: 7,
                nonce: 3,
                gas_price: 9,
                gas_limit: 21_007,
                to: TxKind::Call(to),
                value,
                access_list: list.clone(),
                input: input.clone(),
            }),
            TxEnvelope::Eip1559(TxEip1559 {
                chain_id: 7,
                nonce: 3,
                gas_limit: 21_007,
                max_fee_per_gas: 13,
                max_priority_fee_per_gas: 2,
                to: TxKind::Call(to),
                value,
                access_list: list.clone(),
                input: input.clone(),
            }),
            TxEnvelope::Eip4844(
                TxEip4844 {
                    chain_id: 7,
                    nonce: 3,
                    gas_limit: 21_007,
                    max_fee_per_gas: 13,
                    max_priority_fee_per_gas: 2,
                    to,
                    value,
                    access_list: list.clone(),
                    blob_versioned_hashes: vec![B256::repeat_byte(1)],
                    max_fee_per_blob_gas: 5,
                    input: input.clone(),
                }
                .into(),
            ),
            TxEnvelope::from(TxEip7702 {
                chain_id: 7,
                nonce: 3,
                gas_limit: 21_007,
                max_fee_per_gas: 13,
                max_priority_fee_per_gas: 2,
                to,
                value,
                access_list: list.clone(),
                authorization_list: vec![auth.clone()],
                input: input.clone(),
            }),
        ];
        for (i, tx) in envelopes.iter().enumerate() {
            let legacy = matches!(tx, TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_));
            assert_eq!(Transaction::chain_id(tx), Some(7), "{i}");
            assert_eq!(Transaction::nonce(tx), 3, "{i}");
            assert_eq!(Transaction::gas_limit(tx), 21_007, "{i}");
            assert_eq!(Transaction::gas_price(tx), legacy.then_some(9), "{i}");
            assert_eq!(Transaction::max_fee_per_gas(tx), if legacy { 9 } else { 13 }, "{i}");
            assert_eq!(Transaction::max_priority_fee_per_gas(tx), (!legacy).then_some(2), "{i}");
            let blob = matches!(tx, TxEnvelope::Eip4844(_));
            assert_eq!(Transaction::max_fee_per_blob_gas(tx), blob.then_some(5), "{i}");
            assert_eq!(Transaction::priority_fee_or_price(tx), if legacy { 9 } else { 2 }, "{i}");
            assert_eq!(Transaction::effective_gas_price(tx, Some(1)), if legacy { 9 } else { 3 });
            assert_eq!(Transaction::is_dynamic_fee(tx), !legacy, "{i}");
            let kind = if i == 0 { TxKind::Create } else { TxKind::Call(to) };
            assert_eq!(Transaction::kind(tx), kind, "{i}");
            assert_eq!(Transaction::is_create(tx), i == 0, "{i}");
            assert_eq!(Transaction::value(tx), value, "{i}");
            assert_eq!(Transaction::input(tx), &input, "{i}");
            let has_list = !matches!(tx, TxEnvelope::Legacy(_));
            assert_eq!(Transaction::access_list(tx), has_list.then_some(&list), "{i}");
            let hashes = [B256::repeat_byte(1)];
            assert_eq!(Transaction::blob_versioned_hashes(tx), blob.then_some(&hashes[..]), "{i}");
            let auths = [auth.clone()];
            let set_code = matches!(tx, TxEnvelope::Eip7702(_));
            assert_eq!(Transaction::authorization_list(tx), set_code.then_some(&auths[..]), "{i}");
        }
    }

    /// The validation bounds take the limit itself: a gas limit at the block's, an execution
    /// requirement at the cap and initcode at the size limit pass, one more fails.
    #[test]
    fn validation_bounds_admit_the_limit_itself() {
        let prague = Version::new(SpecId::PRAGUE);
        assert_eq!(validate_block_gas_limit(&prague, 1, U256::ONE), Ok(()));

        let amsterdam = Version::new(SpecId::AMSTERDAM);
        let (_, cap) = amsterdam.tx_gas_caps();
        // A gas limit at the execution cap is not checked further.
        assert_eq!(validate_execution_gas_limit_cap(&amsterdam, cap, cap + 1, 0), Ok(()));
        assert_eq!(validate_execution_gas_limit_cap(&amsterdam, cap + 1, cap, 0), Ok(()));
        let over = Err(HandlerError::IntrinsicGasGreaterThanCap { required: cap + 1, cap });
        assert_eq!(validate_execution_gas_limit_cap(&amsterdam, cap + 1, cap + 1, 0), over);
        assert_eq!(validate_execution_gas_limit_cap(&amsterdam, cap + 1, 0, cap + 1), over);

        let shanghai = Version::new(SpecId::SHANGHAI);
        let max = shanghai.max_initcode_size;
        let code = |len: usize| Bytes::from(vec![0u8; len]);
        assert_eq!(validate_create_initcode(&shanghai, TxKind::Create, &code(max)), Ok(()));
        assert_eq!(
            validate_create_initcode(&shanghai, TxKind::Create, &code(max + 1)),
            Err(HandlerError::CreateInitCodeSizeLimit { limit: max, got: max + 1 })
        );
        let call = TxKind::Call(Address::ZERO);
        assert_eq!(validate_create_initcode(&shanghai, call, &code(max + 1)), Ok(()));
    }

    #[test]
    fn access_list_counts_count_accounts_and_keys() {
        use alloy_eips::eip2930::AccessListItem;
        let item = |byte, keys: usize| AccessListItem {
            address: Address::with_last_byte(byte),
            storage_keys: vec![B256::ZERO; keys],
        };
        assert_eq!(access_list_counts(&AccessList(vec![item(1, 2), item(2, 1)])), (2, 3));
    }

    /// The upfront state gas is taken from the reservoir first and spills into the execution gas.
    #[test]
    fn initial_state_gas_draws_the_reservoir_first() {
        let mut version = Version::new(SpecId::AMSTERDAM);
        version.tx_gas_limit_cap = 100_000;
        // 101,000 less 21,000 of intrinsic gas: 79,000 of execution gas and 1,000 of reservoir.
        assert_eq!(initial_gas_and_reservoir(&version, 101_000, 21_000, 0), (79_000, 1_000));
        assert_eq!(initial_gas_and_reservoir(&version, 101_000, 21_000, 400), (79_000, 600));
        assert_eq!(initial_gas_and_reservoir(&version, 101_000, 21_000, 1_500), (78_500, 0));
    }

    fn evm_with(
        spec: SpecId,
        version: Version,
        database: InMemoryDB,
    ) -> Evm<'static, BaseEvmTypes> {
        let block =
            BlockEnvExt { beneficiary: Address::with_last_byte(0xcc), ..Default::default() };
        Evm::<BaseEvmTypes>::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(spec, version),
            spec,
            block,
            ethereum_tx_registry(spec),
            database,
            Precompiles::base(spec),
        )
    }

    /// EIP-3607 refuses a sender with code but not one with an EIP-7702 delegation; a top-up
    /// raises a short balance to the upfront charge.
    #[test]
    fn sender_validation_refuses_code_and_tops_up_the_shortfall() {
        let caller = Address::with_last_byte(0xaa);
        let sender = |code: Option<Bytecode>, balance: u64| {
            let mut database = InMemoryDB::default();
            let mut info = AccountInfo::default().with_balance(U256::from(balance));
            if let Some(code) = code {
                info = info.with_code(code);
            }
            database.insert_account_info(&caller, info);
            database
        };
        let prague = |database| evm_with(SpecId::PRAGUE, Version::new(SpecId::PRAGUE), database);
        let code = crate::test_utils::legacy_bytecode([op::STOP]);
        let mut evm = prague(sender(Some(code), 10));
        assert_eq!(
            validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::ZERO),
            Err(HandlerError::RejectCallerWithCode)
        );
        let delegation = Bytecode::new_eip7702(Address::with_last_byte(0xdd));
        let mut evm = prague(sender(Some(delegation), 10));
        assert_eq!(validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::ZERO), Ok(0));
        let mut evm = prague(sender(None, 10));
        assert_eq!(validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::ZERO), Ok(0));

        let mut version = Version::new(SpecId::PRAGUE);
        version.features.remove(EvmFeatures::BALANCE_CHECK);
        version.features.insert(EvmFeatures::BALANCE_TOP_UP);
        let mut evm = evm_with(SpecId::PRAGUE, version, sender(None, 3));
        assert_eq!(validate_sender_and_bump_nonce(&mut evm, caller, 0, U256::from(10)), Ok(0));
        assert_eq!(evm.state.account(&caller).unwrap().balance(), U256::from(10));
    }

    #[test]
    fn base_accounts_and_the_access_list_are_warmed() {
        use alloy_eips::eip2930::AccessListItem;
        let mut evm = evm_with(SpecId::PRAGUE, Version::new(SpecId::PRAGUE), InMemoryDB::default());
        let to = Address::with_last_byte(0xbb);
        warm_base_accounts(&mut evm, TxKind::Call(to));
        assert!(evm.state.prewarm_set().is_warm(&to));
        assert!(evm.state.prewarm_set().is_warm(&Address::with_last_byte(0xcc)));
        let listed = Address::with_last_byte(0xee);
        let key = B256::repeat_byte(3);
        let list = AccessList(vec![AccessListItem { address: listed, storage_keys: vec![key] }]);
        warm_access_list(&mut evm, &list);
        assert!(evm.state.prewarm_set().is_storage_warm(&listed, &b256_to_word(key)));
    }

    /// A first frame that halts gets back the part of its upfront charge the reservoir paid, and
    /// the part execution gas paid is consumed with it, off the state gas spent.
    #[test]
    fn a_halted_first_frame_consumes_the_execution_paid_part_of_its_charge() {
        let mut tx_gas = GasTracker::new_with_execution_gas_and_reservoir(100_000, 150_000);
        tx_gas.spend_state(180_000).unwrap();
        let mut result = MessageResultExt::<()> {
            stop: InstrStop::InvalidFEOpcode,
            gas: GasTracker::new_spent_with_reservoir(70_000, 0),
            ..MessageResultExt::default()
        };
        settle_initial_frame_gas_into_reservoir(&mut tx_gas, &mut result, 180_000, 150_000);
        assert_eq!(
            (tx_gas.remaining(), tx_gas.reservoir(), tx_gas.state_gas_spent()),
            (0, 150_000, 0)
        );
    }

    /// A creation transaction that deploys keeps its account's state gas, under either give-back
    /// rule; one onto an address that already holds a balance creates no account and is charged
    /// none.
    #[test]
    fn a_deploying_creation_transaction_keeps_its_account_charge() {
        let caller = Address::with_last_byte(0xaa);
        for (refills, funded) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut version = Version::new(SpecId::AMSTERDAM);
            version.features.set(EvmFeatures::EIP8037_RESERVOIR_REFILLS, refills);
            let price = version.gas_params.get(GasId::CreateState);
            let mut database = InMemoryDB::default();
            database.insert_account_info(
                &caller,
                AccountInfo::default().with_balance(U256::from(u64::MAX)),
            );
            if funded {
                database.insert_account_info(
                    &caller.create(0),
                    AccountInfo::default().with_balance(U256::from(1)),
                );
            }
            let mut evm = evm_with(SpecId::AMSTERDAM, version, database);
            let tx = Recovered::new_unchecked(
                TxEnvelope::Legacy(TxLegacy {
                    gas_limit: 1_000_000,
                    to: TxKind::Create,
                    input: vec![op::PUSH0, op::PUSH0, op::RETURN].into(),
                    ..Default::default()
                }),
                caller,
            );
            let result = evm.transact(&tx).unwrap().discard();
            let case = format!("refills={refills} funded={funded}");
            assert!(result.is_success(), "{case}");
            assert_eq!(result.state_gas_spent(), if funded { 0 } else { price }, "{case}");
        }
    }

    /// Clearing a slot set before the transaction refunds 4,800, which the result reports.
    #[test]
    fn the_result_reports_the_refund() {
        let caller = Address::with_last_byte(0xaa);
        let target = Address::with_last_byte(0xbb);
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &caller,
            AccountInfo::default().with_balance(U256::from(u64::MAX)),
        );
        database.insert_account_info(
            &target,
            AccountInfo::default().with_nonce(1).with_code(crate::test_utils::legacy_bytecode([
                op::PUSH0,
                op::PUSH0,
                op::SSTORE,
            ])),
        );
        database.insert_account_storage(&target, &U256::ZERO, &U256::from(1));
        let mut evm = evm_with(SpecId::PRAGUE, Version::new(SpecId::PRAGUE), database);
        let tx = Recovered::new_unchecked(
            TxEnvelope::Legacy(TxLegacy {
                gas_limit: 100_000,
                to: TxKind::Call(target),
                ..Default::default()
            }),
            caller,
        );
        let result = evm.transact(&tx).unwrap().discard();
        assert!(result.is_success());
        assert_eq!(result.refunded, 4_800);
    }

    fn delegated_world() -> InMemoryDB {
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &Address::with_last_byte(0xaa),
            AccountInfo::default().with_balance(U256::from(u64::MAX)),
        );
        let stop = crate::test_utils::legacy_bytecode([op::STOP]);
        database.insert_account_info(
            &Address::with_last_byte(0xbb),
            AccountInfo::default().with_code(Bytecode::new_eip7702(Address::with_last_byte(0xdd))),
        );
        database.insert_account_info(
            &Address::with_last_byte(0xbc),
            AccountInfo::default().with_nonce(1).with_code(stop.clone()),
        );
        database.insert_account_info(
            &Address::with_last_byte(0xdd),
            AccountInfo::default().with_nonce(1).with_code(stop),
        );
        database
    }

    fn run_delegated(to: u8, list: AccessList, gas_limit: u64) -> TxResult<BaseEvmTypes> {
        let version = Version::new(SpecId::AMSTERDAM);
        let mut evm = evm_with(SpecId::AMSTERDAM, version, delegated_world());
        let tx = Recovered::new_unchecked(
            TxEnvelope::Eip2930(TxEip2930 {
                chain_id: 1,
                gas_limit,
                to: TxKind::Call(Address::with_last_byte(to)),
                access_list: list,
                ..Default::default()
            }),
            Address::with_last_byte(0xaa),
        );
        evm.transact(&tx).unwrap().discard()
    }

    /// Under EIP-2780 a call to an EIP-7702 delegated account reads its delegate: warm, a
    /// delegate in the access list costs the warm read alone; cold, its load is made when the gas
    /// left after the warm read covers the cold premium, exactly or more, and not otherwise.
    #[test]
    fn a_delegated_recipient_reads_its_delegate_warm_or_cold() {
        use alloy_eips::eip2930::AccessListItem;
        let listed = AccessList(vec![AccessListItem {
            address: Address::with_last_byte(0xdd),
            storage_keys: vec![],
        }]);
        let delegated = run_delegated(0xbb, listed.clone(), 1_000_000);
        let plain = run_delegated(0xbc, listed, 1_000_000);
        assert!(delegated.is_success() && plain.is_success());
        assert_eq!(delegated.tx_gas_used() - plain.tx_gas_used(), 100);

        let premium = Version::new(SpecId::AMSTERDAM).gas_params.cold_account_additional_cost();
        let cold = run_delegated(0xbb, AccessList::default(), 1_000_000);
        let plain = run_delegated(0xbc, AccessList::default(), 1_000_000);
        assert!(cold.is_success());
        assert_eq!(cold.tx_gas_used() - plain.tx_gas_used(), 100 + premium);
        // The gas the cold read leaves at zero: the delegate is loaded and runs; one less, and the
        // premium cannot be paid.
        let used = cold.tx_gas_used();
        assert!(run_delegated(0xbb, AccessList::default(), used).is_success());
        assert!(!run_delegated(0xbb, AccessList::default(), used - 1).is_success());
    }

    /// A first frame that runs out of gas in the runtime gas phase is reported with the message
    /// it would have run: its kind, depth, budget and reservoir, accounts, input and value.
    #[test]
    fn a_runtime_out_of_gas_first_frame_reports_its_message() {
        use crate::{
            Inspector,
            interpreter::{Interpreter, Message, MessageResult},
        };
        type Seen = (MessageKind, u16, u64, u64, Address, Address, Address, Bytes, U256, Address);
        #[derive(Default)]
        struct Recorder(Vec<Seen>);
        impl Recorder {
            fn see(&mut self, m: &Message<BaseEvmTypes>) {
                self.0.push((
                    m.kind,
                    m.depth,
                    m.gas_limit,
                    m.reservoir,
                    m.destination,
                    m.call_target,
                    m.caller,
                    m.input.clone(),
                    m.value,
                    m.code_address,
                ));
            }
        }
        impl Inspector<BaseEvmTypes> for Recorder {
            fn call(
                &mut self,
                _: &mut Interpreter<'_, '_, BaseEvmTypes>,
                m: &mut Message<BaseEvmTypes>,
            ) -> Option<MessageResult<BaseEvmTypes>> {
                self.see(m);
                None
            }
            fn create(
                &mut self,
                _: &mut Interpreter<'_, '_, BaseEvmTypes>,
                m: &mut Message<BaseEvmTypes>,
            ) -> Option<MessageResult<BaseEvmTypes>> {
                self.see(m);
                None
            }
        }
        let caller = Address::with_last_byte(0xaa);
        let empty = Address::with_last_byte(0xee);
        for to in [TxKind::Create, TxKind::Call(empty)] {
            let mut version = Version::new(SpecId::AMSTERDAM);
            version.initial_call_depth = 2;
            version.tx_gas_limit_cap = 100_000;
            let mut database = InMemoryDB::default();
            database.insert_account_info(
                &caller,
                AccountInfo::default().with_balance(U256::from(u64::MAX)),
            );
            let mut evm = evm_with(SpecId::AMSTERDAM, version, database);
            evm.set_inspector(Recorder::default());
            let input = Bytes::from_static(&[op::INVALID, 2]);
            let tx = Recovered::new_unchecked(
                TxEnvelope::Legacy(TxLegacy {
                    gas_limit: 150_000,
                    to,
                    value: U256::from(5),
                    input: input.clone(),
                    ..Default::default()
                }),
                caller,
            );
            let result = evm.transact(&tx).unwrap().discard();
            assert_eq!(result.stop, InstrStop::OutOfGas, "{to:?}");
            let seen = &evm.inspector().unwrap().downcast_ref::<Recorder>().unwrap().0;
            // The execution cap less the intrinsic gas (the two nonzero calldata bytes' 32, and a
            // creation's 3,000 and initcode word), and the 50,000 above the cap as the reservoir.
            let (kind, budget, destination) = match to {
                TxKind::Create => (MessageKind::Create, 100_000 - 24_034, caller.create(0)),
                TxKind::Call(to) => (MessageKind::Call, 100_000 - 21_032, to),
            };
            assert_eq!(
                seen[..],
                [(
                    kind,
                    2,
                    budget,
                    50_000,
                    destination,
                    destination,
                    caller,
                    input,
                    U256::from(5),
                    destination
                )],
                "{to:?}"
            );
        }
    }
}
