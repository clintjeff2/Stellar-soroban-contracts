#![no_std]

//! # Decentralized Oracle Network for Price Feeds
//!
//! Provides tamper-proof, multi-source price data through a decentralized network of
//! oracle providers. Features include weighted median aggregation, a reputation system,
//! staleness detection, outlier rejection, and heartbeat monitoring.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Symbol,
    Vec,
};

// ============================================================================
// Storage Keys
// ============================================================================

const _ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const NET_CFG: Symbol = symbol_short!("NET_CFG");

// Prefixed keys – combined with a secondary component at runtime
const ORACLE_PFX: Symbol = symbol_short!("ORA");
const FEED_PFX: Symbol = symbol_short!("FEED");
const PRICE_PFX: Symbol = symbol_short!("PRICE");
const HIST_PFX: Symbol = symbol_short!("HIST");
const SUB_PFX: Symbol = symbol_short!("SUB");
const ORACLE_LST: Symbol = symbol_short!("ORA_LST");
const FEED_LST: Symbol = symbol_short!("FEED_LST");
const ROUND_PFX: Symbol = symbol_short!("ROUND");

// ============================================================================
// Defaults
// ============================================================================

const DEFAULT_MIN_ORACLES: u32 = 3;
const DEFAULT_MAX_ORACLES: u32 = 21;
const DEFAULT_SUBMISSION_WINDOW_SECS: u64 = 300; // 5 min
const DEFAULT_STALENESS_SECS: u64 = 3600; // 1 hour
const DEFAULT_OUTLIER_THRESHOLD_BPS: u32 = 1500; // 15 %
const DEFAULT_MIN_STAKE: i128 = 10_000_000; // 1 XLM in stroops (7 dec)
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 600; // 10 min
const DEFAULT_REP_INITIAL: u32 = 500; // out of 1000
const DEFAULT_REP_MAX: u32 = 1000;
const DEFAULT_REP_REWARD: u32 = 5; // +5 on good submission
const DEFAULT_REP_PENALTY: u32 = 20; // -20 on bad behaviour
const DEFAULT_REP_MISS_PENALTY: u32 = 10; // -10 on missed round
const MAX_HISTORY_LEN: u32 = 50;
const MAX_FEEDS: u32 = 100;

// ============================================================================
// Errors
// ============================================================================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum OracleNetworkError {
    // General
    Unauthorized = 1,
    Paused = 2,
    AlreadyInitialized = 3,
    NotInitialized = 4,
    InvalidInput = 5,

    // Oracle provider
    OracleAlreadyRegistered = 10,
    OracleNotRegistered = 11,
    OracleInactive = 12,
    InsufficientStake = 13,
    OracleSlashed = 14,
    MaxOraclesReached = 15,
    CannotRemoveSelf = 16,

    // Price feeds
    FeedAlreadyExists = 20,
    FeedNotFound = 21,
    FeedInactive = 22,
    MaxFeedsReached = 23,

    // Submissions
    DuplicateSubmission = 30,
    SubmissionWindowClosed = 31,
    InvalidPrice = 32,
    RoundNotOpen = 33,

    // Aggregation
    InsufficientSubmissions = 40,
    ConsensusNotReached = 41,
    StalePrice = 42,
    OutlierRejected = 43,
    NoResolvedPrice = 44,

    // Reputation
    ReputationTooLow = 50,
}

// ============================================================================
// Types
// ============================================================================

/// Global network configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Admin address
    pub admin: Address,
    /// Minimum oracles to register before network is operational
    pub min_oracles: u32,
    /// Maximum oracle providers allowed
    pub max_oracles: u32,
    /// Window (seconds) in which oracles can submit for a round
    pub submission_window_secs: u64,
    /// Price staleness threshold (seconds)
    pub staleness_secs: u64,
    /// Outlier threshold in basis points (10000 = 100 %)
    pub outlier_threshold_bps: u32,
    /// Minimum stake required to register as oracle (stroops)
    pub min_stake: i128,
    /// Heartbeat interval (seconds) – oracle must ping within this
    pub heartbeat_interval: u64,
    /// Initial reputation score for new oracles (0-1000)
    pub rep_initial: u32,
    /// Max reputation score
    pub rep_max: u32,
    /// Reputation reward per valid submission
    pub rep_reward: u32,
    /// Reputation penalty for outlier / bad data
    pub rep_penalty: u32,
    /// Reputation penalty for missing a round
    pub rep_miss_penalty: u32,
}

/// An oracle provider in the network.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleProvider {
    /// Provider address
    pub address: Address,
    /// Amount staked (stroops)
    pub stake: i128,
    /// Reputation score (0 – rep_max)
    pub reputation: u32,
    /// Whether actively participating
    pub is_active: bool,
    /// Timestamp of registration
    pub registered_at: u64,
    /// Last heartbeat timestamp
    pub last_heartbeat: u64,
    /// Total submissions made
    pub total_submissions: u64,
    /// Submissions that were included in consensus
    pub accepted_submissions: u64,
    /// Submissions rejected as outliers
    pub rejected_submissions: u64,
    /// Number of missed rounds
    pub missed_rounds: u64,
}

/// A price feed definition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceFeed {
    /// Unique feed identifier (e.g. hash of "XLM/USD")
    pub feed_id: Symbol,
    /// Human-readable base asset symbol (e.g. "XLM")
    pub base_asset: Symbol,
    /// Human-readable quote asset symbol (e.g. "USD")
    pub quote_asset: Symbol,
    /// Number of decimals in the price (e.g. 8 means price × 10^8)
    pub decimals: u32,
    /// Whether this feed is active
    pub is_active: bool,
    /// Custom staleness override (0 = use network default)
    pub staleness_override_secs: u64,
    /// Custom min-oracles override (0 = use network default)
    pub min_oracles_override: u32,
    /// Timestamp of creation
    pub created_at: u64,
}

/// A single price submission from an oracle for a round.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceSubmission {
    /// The oracle that submitted
    pub oracle: Address,
    /// Price value (scaled by feed decimals)
    pub price: i128,
    /// Ledger timestamp of submission
    pub timestamp: u64,
    /// Confidence (0-10000 bps, self-reported)
    pub confidence: u32,
}

/// A price round – collects submissions, then resolves.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceRound {
    /// Round number
    pub round_id: u64,
    /// Feed this round belongs to
    pub feed_id: Symbol,
    /// When round was opened
    pub opened_at: u64,
    /// When the submission window closes
    pub closes_at: u64,
    /// Whether the round has been resolved
    pub resolved: bool,
}

/// The resolved (aggregated) price for a feed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPrice {
    /// Feed identifier
    pub feed_id: Symbol,
    /// Round that produced this price
    pub round_id: u64,
    /// Aggregated price (weighted median)
    pub price: i128,
    /// Timestamp of resolution
    pub timestamp: u64,
    /// Number of submissions included
    pub num_included: u32,
    /// Number of submissions rejected as outliers
    pub num_rejected: u32,
    /// Spread: (max_included - min_included) in bps of median
    pub spread_bps: u32,
    /// Weighted confidence (bps)
    pub confidence: u32,
}

/// A historical price entry (compact).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceHistoryEntry {
    pub round_id: u64,
    pub price: i128,
    pub timestamp: u64,
    pub num_oracles: u32,
}

/// Oracle performance statistics (read-only view).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleStats {
    pub address: Address,
    pub reputation: u32,
    pub total_submissions: u64,
    pub accepted_submissions: u64,
    pub rejected_submissions: u64,
    pub missed_rounds: u64,
    pub accuracy_bps: u32, // accepted / total × 10000
    pub is_active: bool,
}

/// Network-wide statistics.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkStats {
    pub total_oracles: u32,
    pub active_oracles: u32,
    pub total_feeds: u32,
    pub active_feeds: u32,
    pub total_rounds_resolved: u64,
}

// ============================================================================
// Contract
// ============================================================================

#[contract]
pub struct OracleNetworkContract;

// ============================================================================
// Internal helpers
// ============================================================================

fn require_admin(env: &Env) -> Result<Address, OracleNetworkError> {
    let cfg: NetworkConfig = env
        .storage()
        .persistent()
        .get(&NET_CFG)
        .ok_or(OracleNetworkError::NotInitialized)?;
    cfg.admin.require_auth();
    Ok(cfg.admin)
}

fn get_config(env: &Env) -> Result<NetworkConfig, OracleNetworkError> {
    env.storage()
        .persistent()
        .get(&NET_CFG)
        .ok_or(OracleNetworkError::NotInitialized)
}

fn require_not_paused(env: &Env) -> Result<(), OracleNetworkError> {
    let paused: bool = env.storage().persistent().get(&PAUSED).unwrap_or(false);
    if paused {
        return Err(OracleNetworkError::Paused);
    }
    Ok(())
}

fn get_oracle_list(env: &Env) -> Vec<Address> {
    env.storage()
        .persistent()
        .get(&ORACLE_LST)
        .unwrap_or_else(|| Vec::new(env))
}

fn set_oracle_list(env: &Env, list: &Vec<Address>) {
    env.storage().persistent().set(&ORACLE_LST, list);
}

fn oracle_key(addr: &Address) -> (Symbol, Address) {
    (ORACLE_PFX, addr.clone())
}

fn get_oracle(env: &Env, addr: &Address) -> Result<OracleProvider, OracleNetworkError> {
    env.storage()
        .persistent()
        .get(&oracle_key(addr))
        .ok_or(OracleNetworkError::OracleNotRegistered)
}

fn set_oracle(env: &Env, provider: &OracleProvider) {
    env.storage()
        .persistent()
        .set(&oracle_key(&provider.address), provider);
}

fn get_feed_list(env: &Env) -> Vec<Symbol> {
    env.storage()
        .persistent()
        .get(&FEED_LST)
        .unwrap_or_else(|| Vec::new(env))
}

fn set_feed_list(env: &Env, list: &Vec<Symbol>) {
    env.storage().persistent().set(&FEED_LST, list);
}

fn feed_key(feed_id: &Symbol) -> (Symbol, Symbol) {
    (FEED_PFX, feed_id.clone())
}

fn get_feed(env: &Env, feed_id: &Symbol) -> Result<PriceFeed, OracleNetworkError> {
    env.storage()
        .persistent()
        .get(&feed_key(feed_id))
        .ok_or(OracleNetworkError::FeedNotFound)
}

fn set_feed(env: &Env, feed: &PriceFeed) {
    env.storage()
        .persistent()
        .set(&feed_key(&feed.feed_id), feed);
}

fn round_key(feed_id: &Symbol) -> (Symbol, Symbol) {
    (ROUND_PFX, feed_id.clone())
}

fn submissions_key(feed_id: &Symbol, round_id: u64) -> (Symbol, Symbol, u64) {
    (SUB_PFX, feed_id.clone(), round_id)
}

fn price_key(feed_id: &Symbol) -> (Symbol, Symbol) {
    (PRICE_PFX, feed_id.clone())
}

fn history_key(feed_id: &Symbol) -> (Symbol, Symbol) {
    (HIST_PFX, feed_id.clone())
}

// ---- Math helpers ----

/// Sort a `Vec<(i128, u32)>` by the i128 component (price). Returns a new sorted Vec.
fn sort_by_price(_env: &Env, data: &Vec<(i128, u32)>) -> Vec<(i128, u32)> {
    let len = data.len();
    let mut sorted = data.clone();
    // Simple insertion sort – fine for bounded small sets (max 21)
    for i in 1..len {
        let val = sorted.get(i).unwrap();
        let mut j = i;
        while j > 0 {
            let prev = sorted.get(j - 1).unwrap();
            if prev.0 > val.0 {
                sorted.set(j, prev);
                j -= 1;
            } else {
                break;
            }
        }
        sorted.set(j, val);
    }
    sorted
}

/// Weighted median: each oracle's submission carries weight = reputation score.
/// Returns the price at cumulative weight ≥ half of total weight.
fn weighted_median(env: &Env, prices_and_weights: &Vec<(i128, u32)>) -> i128 {
    if prices_and_weights.is_empty() {
        return 0;
    }
    if prices_and_weights.len() == 1 {
        return prices_and_weights.get(0).unwrap().0;
    }

    let sorted = sort_by_price(env, prices_and_weights);

    let mut total_weight: u64 = 0;
    for i in 0..sorted.len() {
        total_weight += sorted.get(i).unwrap().1 as u64;
    }

    let half = (total_weight + 1) / 2;
    let mut cumulative: u64 = 0;
    for i in 0..sorted.len() {
        let (p, w) = sorted.get(i).unwrap();
        cumulative += w as u64;
        if cumulative >= half {
            return p;
        }
    }

    // Fallback – last price
    sorted.get(sorted.len() - 1).unwrap().0
}

/// Simple median (unweighted) for outlier detection reference.
fn simple_median(_env: &Env, values: &Vec<i128>) -> i128 {
    if values.is_empty() {
        return 0;
    }
    let len = values.len();
    let mut sorted = values.clone();
    for i in 1..len {
        let val = sorted.get(i).unwrap();
        let mut j = i;
        while j > 0 {
            if sorted.get(j - 1).unwrap() > val {
                sorted.set(j, sorted.get(j - 1).unwrap());
                j -= 1;
            } else {
                break;
            }
        }
        sorted.set(j, val);
    }
    if len % 2 == 1 {
        sorted.get(len / 2).unwrap()
    } else {
        let a = sorted.get(len / 2 - 1).unwrap();
        let b = sorted.get(len / 2).unwrap();
        (a + b) / 2
    }
}

/// Check if a price is an outlier relative to the median.
/// Returns true if |price - median| / |median| > threshold_bps / 10000.
fn is_outlier(price: i128, median: i128, threshold_bps: u32) -> bool {
    if median == 0 {
        return price != 0;
    }
    let diff = if price > median {
        price - median
    } else {
        median - price
    };
    // diff * 10000 / |median| > threshold_bps
    let scaled_diff = diff.saturating_mul(10_000);
    let abs_median = if median < 0 { -median } else { median };
    (scaled_diff / abs_median) > threshold_bps as i128
}

/// Calculate spread in bps between max and min relative to median.
fn calculate_spread_bps(min_val: i128, max_val: i128, median: i128) -> u32 {
    if median == 0 {
        return 0;
    }
    let range = max_val - min_val;
    let abs_median = if median < 0 { -median } else { median };
    let bps = (range.saturating_mul(10_000)) / abs_median;
    if bps > u32::MAX as i128 {
        u32::MAX
    } else {
        bps as u32
    }
}

/// Weighted average confidence.
fn weighted_confidence(submissions: &[(u32, u32)]) -> u32 {
    // submissions: (confidence_bps, weight)
    if submissions.is_empty() {
        return 0;
    }
    let mut sum: u64 = 0;
    let mut total_w: u64 = 0;
    for (c, w) in submissions {
        sum += (*c as u64) * (*w as u64);
        total_w += *w as u64;
    }
    if total_w == 0 {
        return 0;
    }
    (sum / total_w) as u32
}

// ============================================================================
// Contract Implementation
// ============================================================================

#[allow(deprecated)]
#[contractimpl]
impl OracleNetworkContract {
    // ── Initialization ──────────────────────────────────────────────────────

    /// Initialize the oracle network with an admin and optional custom config.
    pub fn initialize(env: Env, admin: Address) -> Result<(), OracleNetworkError> {
        if env.storage().persistent().has(&NET_CFG) {
            return Err(OracleNetworkError::AlreadyInitialized);
        }
        admin.require_auth();

        let cfg = NetworkConfig {
            admin: admin.clone(),
            min_oracles: DEFAULT_MIN_ORACLES,
            max_oracles: DEFAULT_MAX_ORACLES,
            submission_window_secs: DEFAULT_SUBMISSION_WINDOW_SECS,
            staleness_secs: DEFAULT_STALENESS_SECS,
            outlier_threshold_bps: DEFAULT_OUTLIER_THRESHOLD_BPS,
            min_stake: DEFAULT_MIN_STAKE,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            rep_initial: DEFAULT_REP_INITIAL,
            rep_max: DEFAULT_REP_MAX,
            rep_reward: DEFAULT_REP_REWARD,
            rep_penalty: DEFAULT_REP_PENALTY,
            rep_miss_penalty: DEFAULT_REP_MISS_PENALTY,
        };

        env.storage().persistent().set(&NET_CFG, &cfg);
        env.storage().persistent().set(&PAUSED, &false);
        set_oracle_list(&env, &Vec::new(&env));
        set_feed_list(&env, &Vec::new(&env));

        env.events().publish(
            (symbol_short!("init"), symbol_short!("network")),
            admin,
        );

        Ok(())
    }

    // ── Admin functions ─────────────────────────────────────────────────────

    /// Pause / unpause the network.
    pub fn set_paused(env: Env, paused: bool) -> Result<(), OracleNetworkError> {
        let _admin = require_admin(&env)?;
        env.storage().persistent().set(&PAUSED, &paused);
        env.events()
            .publish((symbol_short!("admin"), symbol_short!("pause")), paused);
        Ok(())
    }

    /// Update network configuration parameters.
    pub fn update_config(
        env: Env,
        min_oracles: u32,
        max_oracles: u32,
        submission_window_secs: u64,
        staleness_secs: u64,
        outlier_threshold_bps: u32,
        min_stake: i128,
        heartbeat_interval: u64,
    ) -> Result<(), OracleNetworkError> {
        let _admin = require_admin(&env)?;

        if min_oracles == 0
            || max_oracles < min_oracles
            || submission_window_secs == 0
            || staleness_secs == 0
            || outlier_threshold_bps == 0
            || outlier_threshold_bps > 10_000
            || min_stake < 0
            || heartbeat_interval == 0
        {
            return Err(OracleNetworkError::InvalidInput);
        }

        let mut cfg = get_config(&env)?;
        cfg.min_oracles = min_oracles;
        cfg.max_oracles = max_oracles;
        cfg.submission_window_secs = submission_window_secs;
        cfg.staleness_secs = staleness_secs;
        cfg.outlier_threshold_bps = outlier_threshold_bps;
        cfg.min_stake = min_stake;
        cfg.heartbeat_interval = heartbeat_interval;
        env.storage().persistent().set(&NET_CFG, &cfg);

        env.events().publish(
            (symbol_short!("admin"), symbol_short!("config")),
            min_oracles,
        );
        Ok(())
    }

    /// Update reputation parameters.
    pub fn update_reputation_config(
        env: Env,
        rep_initial: u32,
        rep_max: u32,
        rep_reward: u32,
        rep_penalty: u32,
        rep_miss_penalty: u32,
    ) -> Result<(), OracleNetworkError> {
        let _admin = require_admin(&env)?;

        if rep_max == 0 || rep_initial > rep_max || rep_reward > rep_max || rep_penalty > rep_max {
            return Err(OracleNetworkError::InvalidInput);
        }

        let mut cfg = get_config(&env)?;
        cfg.rep_initial = rep_initial;
        cfg.rep_max = rep_max;
        cfg.rep_reward = rep_reward;
        cfg.rep_penalty = rep_penalty;
        cfg.rep_miss_penalty = rep_miss_penalty;
        env.storage().persistent().set(&NET_CFG, &cfg);
        Ok(())
    }

    // ── Oracle Provider Management ──────────────────────────────────────────

    /// Register a new oracle provider with a stake.
    pub fn register_oracle(
        env: Env,
        oracle_address: Address,
        stake: i128,
    ) -> Result<(), OracleNetworkError> {
        require_not_paused(&env)?;
        oracle_address.require_auth();
        let cfg = get_config(&env)?;

        // Check stake
        if stake < cfg.min_stake {
            return Err(OracleNetworkError::InsufficientStake);
        }

        // Check max oracles
        let mut list = get_oracle_list(&env);
        if list.len() as u32 >= cfg.max_oracles {
            return Err(OracleNetworkError::MaxOraclesReached);
        }

        // Check not already registered
        for i in 0..list.len() {
            if list.get(i).unwrap() == oracle_address {
                return Err(OracleNetworkError::OracleAlreadyRegistered);
            }
        }

        let now = env.ledger().timestamp();

        let provider = OracleProvider {
            address: oracle_address.clone(),
            stake,
            reputation: cfg.rep_initial,
            is_active: true,
            registered_at: now,
            last_heartbeat: now,
            total_submissions: 0,
            accepted_submissions: 0,
            rejected_submissions: 0,
            missed_rounds: 0,
        };

        set_oracle(&env, &provider);
        list.push_back(oracle_address.clone());
        set_oracle_list(&env, &list);

        env.events().publish(
            (symbol_short!("oracle"), symbol_short!("register")),
            oracle_address,
        );

        Ok(())
    }

    /// Deactivate an oracle (admin or self).
    pub fn deactivate_oracle(
        env: Env,
        oracle_address: Address,
    ) -> Result<(), OracleNetworkError> {
        // Either admin or the oracle itself
        let cfg = get_config(&env)?;
        let _is_admin = cfg.admin == oracle_address;
        oracle_address.require_auth();

        let mut provider = get_oracle(&env, &oracle_address)?;
        provider.is_active = false;
        set_oracle(&env, &provider);

        env.events().publish(
            (symbol_short!("oracle"), symbol_short!("deactiv")),
            oracle_address,
        );
        Ok(())
    }

    /// Reactivate an oracle.
    pub fn reactivate_oracle(
        env: Env,
        oracle_address: Address,
    ) -> Result<(), OracleNetworkError> {
        require_not_paused(&env)?;
        oracle_address.require_auth();

        let cfg = get_config(&env)?;
        let mut provider = get_oracle(&env, &oracle_address)?;

        // Require minimum reputation to reactivate
        if provider.reputation < cfg.rep_initial / 2 {
            return Err(OracleNetworkError::ReputationTooLow);
        }

        provider.is_active = true;
        provider.last_heartbeat = env.ledger().timestamp();
        set_oracle(&env, &provider);

        env.events().publish(
            (symbol_short!("oracle"), symbol_short!("reactiv")),
            oracle_address,
        );
        Ok(())
    }

    /// Add additional stake.
    pub fn add_stake(
        env: Env,
        oracle_address: Address,
        amount: i128,
    ) -> Result<(), OracleNetworkError> {
        require_not_paused(&env)?;
        oracle_address.require_auth();

        if amount <= 0 {
            return Err(OracleNetworkError::InvalidInput);
        }

        let mut provider = get_oracle(&env, &oracle_address)?;
        provider.stake = provider.stake.saturating_add(amount);
        set_oracle(&env, &provider);
        Ok(())
    }

    /// Oracle heartbeat – proves liveness.
    pub fn heartbeat(env: Env, oracle_address: Address) -> Result<(), OracleNetworkError> {
        require_not_paused(&env)?;
        oracle_address.require_auth();

        let mut provider = get_oracle(&env, &oracle_address)?;
        if !provider.is_active {
            return Err(OracleNetworkError::OracleInactive);
        }
        provider.last_heartbeat = env.ledger().timestamp();
        set_oracle(&env, &provider);
        Ok(())
    }

    /// Admin: slash an oracle's stake and reputation for misbehaviour.
    pub fn slash_oracle(
        env: Env,
        oracle_address: Address,
        stake_penalty: i128,
        rep_penalty: u32,
    ) -> Result<(), OracleNetworkError> {
        let _admin = require_admin(&env)?;

        let mut provider = get_oracle(&env, &oracle_address)?;

        if stake_penalty > 0 {
            provider.stake = provider.stake.saturating_sub(stake_penalty);
        }
        if rep_penalty > 0 {
            provider.reputation = provider.reputation.saturating_sub(rep_penalty);
        }
        if provider.reputation == 0 {
            provider.is_active = false;
        }

        set_oracle(&env, &provider);

        env.events().publish(
            (symbol_short!("oracle"), symbol_short!("slash")),
            oracle_address,
        );
        Ok(())
    }

    // ── Price Feed Management ───────────────────────────────────────────────

    /// Create a new price feed.
    pub fn create_feed(
        env: Env,
        feed_id: Symbol,
        base_asset: Symbol,
        quote_asset: Symbol,
        decimals: u32,
    ) -> Result<(), OracleNetworkError> {
        let _admin = require_admin(&env)?;

        let mut feeds = get_feed_list(&env);
        if feeds.len() as u32 >= MAX_FEEDS {
            return Err(OracleNetworkError::MaxFeedsReached);
        }

        // Check not existing
        for i in 0..feeds.len() {
            if feeds.get(i).unwrap() == feed_id {
                return Err(OracleNetworkError::FeedAlreadyExists);
            }
        }

        let feed = PriceFeed {
            feed_id: feed_id.clone(),
            base_asset,
            quote_asset,
            decimals,
            is_active: true,
            staleness_override_secs: 0,
            min_oracles_override: 0,
            created_at: env.ledger().timestamp(),
        };

        set_feed(&env, &feed);
        feeds.push_back(feed_id.clone());
        set_feed_list(&env, &feeds);

        env.events().publish(
            (symbol_short!("feed"), symbol_short!("create")),
            feed_id,
        );
        Ok(())
    }

    /// Update a feed's overrides.
    pub fn update_feed(
        env: Env,
        feed_id: Symbol,
        is_active: bool,
        staleness_override_secs: u64,
        min_oracles_override: u32,
    ) -> Result<(), OracleNetworkError> {
        let _admin = require_admin(&env)?;

        let mut feed = get_feed(&env, &feed_id)?;
        feed.is_active = is_active;
        feed.staleness_override_secs = staleness_override_secs;
        feed.min_oracles_override = min_oracles_override;
        set_feed(&env, &feed);

        env.events().publish(
            (symbol_short!("feed"), symbol_short!("update")),
            feed_id,
        );
        Ok(())
    }

    // ── Price Rounds & Submissions ──────────────────────────────────────────

    /// Open a new price round for a feed. Admin or any active oracle can start a round.
    pub fn open_round(
        env: Env,
        caller: Address,
        feed_id: Symbol,
    ) -> Result<u64, OracleNetworkError> {
        require_not_paused(&env)?;
        caller.require_auth();

        let feed = get_feed(&env, &feed_id)?;
        if !feed.is_active {
            return Err(OracleNetworkError::FeedInactive);
        }

        let cfg = get_config(&env)?;
        let now = env.ledger().timestamp();

        // Determine new round id
        let rk = round_key(&feed_id);
        let prev_round: Option<PriceRound> = env.storage().persistent().get(&rk);

        let round_id = match &prev_round {
            Some(pr) => {
                // Previous round must be resolved or expired
                if !pr.resolved && now < pr.closes_at {
                    return Err(OracleNetworkError::RoundNotOpen);
                }
                pr.round_id + 1
            }
            None => 1,
        };

        let round = PriceRound {
            round_id,
            feed_id: feed_id.clone(),
            opened_at: now,
            closes_at: now + cfg.submission_window_secs,
            resolved: false,
        };

        env.storage().persistent().set(&rk, &round);

        // Initialize empty submissions vec
        let empty_subs: Vec<PriceSubmission> = Vec::new(&env);
        env.storage()
            .persistent()
            .set(&submissions_key(&feed_id, round_id), &empty_subs);

        env.events().publish(
            (symbol_short!("round"), symbol_short!("open")),
            (feed_id, round_id),
        );

        Ok(round_id)
    }

    /// Submit a price for the current open round.
    pub fn submit_price(
        env: Env,
        oracle_address: Address,
        feed_id: Symbol,
        price: i128,
        confidence: u32,
    ) -> Result<(), OracleNetworkError> {
        require_not_paused(&env)?;
        oracle_address.require_auth();

        // Validate oracle
        let mut provider = get_oracle(&env, &oracle_address)?;
        if !provider.is_active {
            return Err(OracleNetworkError::OracleInactive);
        }

        // Validate price
        if price <= 0 {
            return Err(OracleNetworkError::InvalidPrice);
        }
        let conf = if confidence > 10_000 { 10_000 } else { confidence };

        // Get current round
        let rk = round_key(&feed_id);
        let round: PriceRound = env
            .storage()
            .persistent()
            .get(&rk)
            .ok_or(OracleNetworkError::RoundNotOpen)?;

        if round.resolved {
            return Err(OracleNetworkError::RoundNotOpen);
        }

        let now = env.ledger().timestamp();
        if now > round.closes_at {
            return Err(OracleNetworkError::SubmissionWindowClosed);
        }

        // Get submissions and check for duplicates
        let sk = submissions_key(&feed_id, round.round_id);
        let mut subs: Vec<PriceSubmission> = env
            .storage()
            .persistent()
            .get(&sk)
            .unwrap_or_else(|| Vec::new(&env));

        for i in 0..subs.len() {
            if subs.get(i).unwrap().oracle == oracle_address {
                return Err(OracleNetworkError::DuplicateSubmission);
            }
        }

        let submission = PriceSubmission {
            oracle: oracle_address.clone(),
            price,
            timestamp: now,
            confidence: conf,
        };

        subs.push_back(submission);
        env.storage().persistent().set(&sk, &subs);

        // Update oracle stats
        provider.total_submissions += 1;
        provider.last_heartbeat = now;
        set_oracle(&env, &provider);

        env.events().publish(
            (symbol_short!("price"), symbol_short!("submit")),
            (feed_id, oracle_address, price),
        );

        Ok(())
    }

    // ── Aggregation & Resolution ────────────────────────────────────────────

    /// Resolve the current round for a feed – aggregate submissions, apply outlier
    /// detection, compute weighted median, update reputation, store result.
    pub fn resolve_round(
        env: Env,
        caller: Address,
        feed_id: Symbol,
    ) -> Result<ResolvedPrice, OracleNetworkError> {
        require_not_paused(&env)?;
        caller.require_auth();

        let cfg = get_config(&env)?;
        let feed = get_feed(&env, &feed_id)?;
        if !feed.is_active {
            return Err(OracleNetworkError::FeedInactive);
        }

        let rk = round_key(&feed_id);
        let mut round: PriceRound = env
            .storage()
            .persistent()
            .get(&rk)
            .ok_or(OracleNetworkError::RoundNotOpen)?;

        if round.resolved {
            return Err(OracleNetworkError::RoundNotOpen);
        }

        let now = env.ledger().timestamp();

        // Allow resolution after window closes, or early if enough submissions
        let sk = submissions_key(&feed_id, round.round_id);
        let subs: Vec<PriceSubmission> = env
            .storage()
            .persistent()
            .get(&sk)
            .unwrap_or_else(|| Vec::new(&env));

        let min_oracles = if feed.min_oracles_override > 0 {
            feed.min_oracles_override
        } else {
            cfg.min_oracles
        };

        if (subs.len() as u32) < min_oracles {
            return Err(OracleNetworkError::InsufficientSubmissions);
        }

        // ---- Step 1: Collect all prices for outlier detection ----
        let mut all_prices: Vec<i128> = Vec::new(&env);
        for i in 0..subs.len() {
            all_prices.push_back(subs.get(i).unwrap().price);
        }
        let reference_median = simple_median(&env, &all_prices);

        // ---- Step 2: Filter outliers, build weighted price set ----
        let outlier_bps = cfg.outlier_threshold_bps;
        let mut included: Vec<(i128, u32)> = Vec::new(&env); // (price, weight)
        let mut conf_data_buf: [(u32, u32); 21] = [(0, 0); 21]; // stack buffer for confidence calc
        let mut conf_count: usize = 0;
        let mut rejected_count: u32 = 0;
        let mut included_min: i128 = i128::MAX;
        let mut included_max: i128 = i128::MIN;

        // Track which oracles submitted and whether they were included/rejected
        let mut oracle_outcomes: Vec<(Address, bool)> = Vec::new(&env); // (addr, was_included)

        for i in 0..subs.len() {
            let sub = subs.get(i).unwrap();
            let outlier = is_outlier(sub.price, reference_median, outlier_bps);

            oracle_outcomes.push_back((sub.oracle.clone(), !outlier));

            if outlier {
                rejected_count += 1;
            } else {
                // Get oracle reputation as weight
                let rep = match get_oracle(&env, &sub.oracle) {
                    Ok(o) => o.reputation,
                    Err(_) => 1, // fallback
                };
                included.push_back((sub.price, rep));

                if sub.price < included_min {
                    included_min = sub.price;
                }
                if sub.price > included_max {
                    included_max = sub.price;
                }
                if conf_count < 21 {
                    conf_data_buf[conf_count] = (sub.confidence, rep);
                    conf_count += 1;
                }
            }
        }

        let included_count = included.len() as u32;
        if included_count < min_oracles {
            return Err(OracleNetworkError::ConsensusNotReached);
        }

        // ---- Step 3: Compute weighted median ----
        let final_price = weighted_median(&env, &included);

        // ---- Step 4: Compute stats ----
        let spread = calculate_spread_bps(included_min, included_max, final_price);
        let conf_val = weighted_confidence(&conf_data_buf[..conf_count]);

        // ---- Step 5: Update oracle reputations ----
        for i in 0..oracle_outcomes.len() {
            let (addr, was_included) = oracle_outcomes.get(i).unwrap();
            if let Ok(mut provider) = get_oracle(&env, &addr) {
                if was_included {
                    provider.accepted_submissions += 1;
                    provider.reputation =
                        core::cmp::min(provider.reputation + cfg.rep_reward, cfg.rep_max);
                } else {
                    provider.rejected_submissions += 1;
                    provider.reputation = provider.reputation.saturating_sub(cfg.rep_penalty);
                    if provider.reputation == 0 {
                        provider.is_active = false;
                    }
                }
                set_oracle(&env, &provider);
            }
        }

        // ---- Step 6: Penalise oracles that missed this round ----
        let oracle_list = get_oracle_list(&env);
        for i in 0..oracle_list.len() {
            let addr = oracle_list.get(i).unwrap();
            // Check if this oracle submitted
            let mut submitted = false;
            for j in 0..oracle_outcomes.len() {
                let (sub_addr, _) = oracle_outcomes.get(j).unwrap();
                if sub_addr == addr {
                    submitted = true;
                    break;
                }
            }
            if !submitted {
                if let Ok(mut provider) = get_oracle(&env, &addr) {
                    if provider.is_active {
                        provider.missed_rounds += 1;
                        provider.reputation =
                            provider.reputation.saturating_sub(cfg.rep_miss_penalty);
                        if provider.reputation == 0 {
                            provider.is_active = false;
                        }
                        set_oracle(&env, &provider);
                    }
                }
            }
        }

        // ---- Step 7: Store resolved price ----
        let resolved = ResolvedPrice {
            feed_id: feed_id.clone(),
            round_id: round.round_id,
            price: final_price,
            timestamp: now,
            num_included: included_count,
            num_rejected: rejected_count,
            spread_bps: spread,
            confidence: conf_val,
        };

        env.storage().persistent().set(&price_key(&feed_id), &resolved);

        // ---- Step 8: Append to history (bounded) ----
        let hk = history_key(&feed_id);
        let mut history: Vec<PriceHistoryEntry> = env
            .storage()
            .persistent()
            .get(&hk)
            .unwrap_or_else(|| Vec::new(&env));

        let entry = PriceHistoryEntry {
            round_id: round.round_id,
            price: final_price,
            timestamp: now,
            num_oracles: included_count,
        };
        history.push_back(entry);

        // Trim if exceeds max
        while history.len() as u32 > MAX_HISTORY_LEN {
            history.remove(0);
        }
        env.storage().persistent().set(&hk, &history);

        // ---- Step 9: Mark round resolved ----
        round.resolved = true;
        env.storage().persistent().set(&rk, &round);

        env.events().publish(
            (symbol_short!("round"), symbol_short!("resolve")),
            (feed_id, round.round_id, final_price),
        );

        Ok(resolved)
    }

    // ── Price Queries (integration surface) ─────────────────────────────────

    /// Get the latest resolved price for a feed.
    /// Returns error if price is stale (exceeds staleness threshold).
    pub fn get_price(
        env: Env,
        feed_id: Symbol,
    ) -> Result<ResolvedPrice, OracleNetworkError> {
        let resolved: ResolvedPrice = env
            .storage()
            .persistent()
            .get(&price_key(&feed_id))
            .ok_or(OracleNetworkError::NoResolvedPrice)?;

        // Staleness check
        let cfg = get_config(&env)?;
        let feed = get_feed(&env, &feed_id)?;
        let staleness = if feed.staleness_override_secs > 0 {
            feed.staleness_override_secs
        } else {
            cfg.staleness_secs
        };

        let now = env.ledger().timestamp();
        if now > resolved.timestamp && (now - resolved.timestamp) > staleness {
            return Err(OracleNetworkError::StalePrice);
        }

        Ok(resolved)
    }

    /// Get the latest price value only (convenience for cross-contract calls).
    pub fn get_price_value(
        env: Env,
        feed_id: Symbol,
    ) -> Result<i128, OracleNetworkError> {
        let resolved = Self::get_price(env, feed_id)?;
        Ok(resolved.price)
    }

    /// Get latest price without staleness check (for historical analysis).
    pub fn get_latest_price_unchecked(
        env: Env,
        feed_id: Symbol,
    ) -> Result<ResolvedPrice, OracleNetworkError> {
        env.storage()
            .persistent()
            .get(&price_key(&feed_id))
            .ok_or(OracleNetworkError::NoResolvedPrice)
    }

    /// Get price history for a feed.
    pub fn get_price_history(
        env: Env,
        feed_id: Symbol,
    ) -> Result<Vec<PriceHistoryEntry>, OracleNetworkError> {
        let hk = history_key(&feed_id);
        env.storage()
            .persistent()
            .get(&hk)
            .ok_or(OracleNetworkError::FeedNotFound)
    }

    /// Get the current open round for a feed (if any).
    pub fn get_current_round(
        env: Env,
        feed_id: Symbol,
    ) -> Result<PriceRound, OracleNetworkError> {
        let rk = round_key(&feed_id);
        env.storage()
            .persistent()
            .get(&rk)
            .ok_or(OracleNetworkError::RoundNotOpen)
    }

    /// Get submissions for a specific round.
    pub fn get_round_submissions(
        env: Env,
        feed_id: Symbol,
        round_id: u64,
    ) -> Result<Vec<PriceSubmission>, OracleNetworkError> {
        let sk = submissions_key(&feed_id, round_id);
        env.storage()
            .persistent()
            .get(&sk)
            .ok_or(OracleNetworkError::RoundNotOpen)
    }

    // ── Oracle & Feed Queries ───────────────────────────────────────────────

    /// Get oracle provider details.
    pub fn get_oracle(
        env: Env,
        oracle_address: Address,
    ) -> Result<OracleProvider, OracleNetworkError> {
        get_oracle(&env, &oracle_address)
    }

    /// Get oracle performance statistics.
    pub fn get_oracle_stats(
        env: Env,
        oracle_address: Address,
    ) -> Result<OracleStats, OracleNetworkError> {
        let provider = get_oracle(&env, &oracle_address)?;
        let accuracy = if provider.total_submissions > 0 {
            ((provider.accepted_submissions * 10_000) / provider.total_submissions) as u32
        } else {
            0
        };

        Ok(OracleStats {
            address: provider.address,
            reputation: provider.reputation,
            total_submissions: provider.total_submissions,
            accepted_submissions: provider.accepted_submissions,
            rejected_submissions: provider.rejected_submissions,
            missed_rounds: provider.missed_rounds,
            accuracy_bps: accuracy,
            is_active: provider.is_active,
        })
    }

    /// List all registered oracle addresses.
    pub fn list_oracles(env: Env) -> Vec<Address> {
        get_oracle_list(&env)
    }

    /// Get feed details.
    pub fn get_feed(
        env: Env,
        feed_id: Symbol,
    ) -> Result<PriceFeed, OracleNetworkError> {
        get_feed(&env, &feed_id)
    }

    /// List all feed ids.
    pub fn list_feeds(env: Env) -> Vec<Symbol> {
        get_feed_list(&env)
    }

    /// Get network-wide statistics.
    pub fn get_network_stats(env: Env) -> Result<NetworkStats, OracleNetworkError> {
        let oracles = get_oracle_list(&env);
        let feeds = get_feed_list(&env);

        let mut active_oracles: u32 = 0;
        for i in 0..oracles.len() {
            if let Ok(o) = get_oracle(&env, &oracles.get(i).unwrap()) {
                if o.is_active {
                    active_oracles += 1;
                }
            }
        }

        let mut active_feeds: u32 = 0;
        let mut total_rounds: u64 = 0;
        for i in 0..feeds.len() {
            let fid = feeds.get(i).unwrap();
            if let Ok(f) = get_feed(&env, &fid) {
                if f.is_active {
                    active_feeds += 1;
                }
            }
            // Count resolved rounds from current round_id
            let rk = round_key(&fid);
            if let Some(r) = env.storage().persistent().get::<_, PriceRound>(&rk) {
                if r.resolved {
                    total_rounds += r.round_id;
                } else if r.round_id > 1 {
                    total_rounds += r.round_id - 1;
                }
            }
        }

        Ok(NetworkStats {
            total_oracles: oracles.len() as u32,
            active_oracles,
            total_feeds: feeds.len() as u32,
            active_feeds,
            total_rounds_resolved: total_rounds,
        })
    }

    /// Get the network configuration.
    pub fn get_config(env: Env) -> Result<NetworkConfig, OracleNetworkError> {
        get_config(&env)
    }

    // ── Convenience: check oracle health ────────────────────────────────────

    /// Check if an oracle has missed its heartbeat deadline.
    pub fn is_oracle_healthy(
        env: Env,
        oracle_address: Address,
    ) -> Result<bool, OracleNetworkError> {
        let provider = get_oracle(&env, &oracle_address)?;
        if !provider.is_active {
            return Ok(false);
        }
        let cfg = get_config(&env)?;
        let now = env.ledger().timestamp();
        let healthy =
            now <= provider.last_heartbeat + cfg.heartbeat_interval && provider.reputation > 0;
        Ok(healthy)
    }

    /// Admin can deactivate oracles that missed heartbeat.
    pub fn enforce_heartbeats(env: Env) -> Result<u32, OracleNetworkError> {
        let _admin = require_admin(&env)?;
        let cfg = get_config(&env)?;
        let now = env.ledger().timestamp();
        let list = get_oracle_list(&env);

        let mut deactivated: u32 = 0;
        for i in 0..list.len() {
            let addr = list.get(i).unwrap();
            if let Ok(mut provider) = get_oracle(&env, &addr) {
                if provider.is_active
                    && now > provider.last_heartbeat + cfg.heartbeat_interval
                {
                    provider.is_active = false;
                    provider.reputation =
                        provider.reputation.saturating_sub(cfg.rep_miss_penalty);
                    set_oracle(&env, &provider);
                    deactivated += 1;
                }
            }
        }
        Ok(deactivated)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::Env;

    fn setup() -> (Env, Address, OracleNetworkContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(OracleNetworkContract, ());
        let client = OracleNetworkContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    fn register_oracles(
        env: &Env,
        client: &OracleNetworkContractClient,
        count: usize,
    ) -> Vec<Address> {
        let mut addrs = Vec::new(env);
        for _ in 0..count {
            let addr = Address::generate(env);
            client.register_oracle(&addr, &DEFAULT_MIN_STAKE);
            addrs.push_back(addr);
        }
        addrs
    }

    fn create_test_feed(
        env: &Env,
        client: &OracleNetworkContractClient,
    ) -> Symbol {
        let feed_id = symbol_short!("XLMUSD");
        let base = symbol_short!("XLM");
        let quote = symbol_short!("USD");
        client.create_feed(&feed_id, &base, &quote, &8);
        feed_id
    }

    // ── Initialization ──────────────────────────────────────────────────

    #[test]
    fn test_initialize() {
        let (env, admin, client) = setup();
        let cfg = client.get_config();
        assert_eq!(cfg.admin, admin);
        assert_eq!(cfg.min_oracles, DEFAULT_MIN_ORACLES);
    }

    #[test]
    fn test_double_init_fails() {
        let (env, admin, client) = setup();
        let result = client.try_initialize(&admin);
        assert!(result.is_err());
    }

    // ── Oracle Management ───────────────────────────────────────────────

    #[test]
    fn test_register_oracle() {
        let (env, _, client) = setup();
        let oracle = Address::generate(&env);
        client.register_oracle(&oracle, &DEFAULT_MIN_STAKE);

        let provider = client.get_oracle(&oracle);
        assert_eq!(provider.address, oracle);
        assert!(provider.is_active);
        assert_eq!(provider.reputation, DEFAULT_REP_INITIAL);
        assert_eq!(provider.stake, DEFAULT_MIN_STAKE);
    }

    #[test]
    fn test_register_duplicate_oracle_fails() {
        let (env, _, client) = setup();
        let oracle = Address::generate(&env);
        client.register_oracle(&oracle, &DEFAULT_MIN_STAKE);
        let result = client.try_register_oracle(&oracle, &DEFAULT_MIN_STAKE);
        assert!(result.is_err());
    }

    #[test]
    fn test_insufficient_stake_fails() {
        let (env, _, client) = setup();
        let oracle = Address::generate(&env);
        let result = client.try_register_oracle(&oracle, &(DEFAULT_MIN_STAKE - 1));
        assert!(result.is_err());
    }

    #[test]
    fn test_deactivate_reactivate_oracle() {
        let (env, _, client) = setup();
        let oracle = Address::generate(&env);
        client.register_oracle(&oracle, &DEFAULT_MIN_STAKE);

        client.deactivate_oracle(&oracle);
        let provider = client.get_oracle(&oracle);
        assert!(!provider.is_active);

        client.reactivate_oracle(&oracle);
        let provider = client.get_oracle(&oracle);
        assert!(provider.is_active);
    }

    #[test]
    fn test_add_stake() {
        let (env, _, client) = setup();
        let oracle = Address::generate(&env);
        client.register_oracle(&oracle, &DEFAULT_MIN_STAKE);
        client.add_stake(&oracle, &1_000_000);

        let provider = client.get_oracle(&oracle);
        assert_eq!(provider.stake, DEFAULT_MIN_STAKE + 1_000_000);
    }

    #[test]
    fn test_heartbeat() {
        let (env, _, client) = setup();
        let oracle = Address::generate(&env);
        client.register_oracle(&oracle, &DEFAULT_MIN_STAKE);
        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.heartbeat(&oracle);

        let provider = client.get_oracle(&oracle);
        assert_eq!(provider.last_heartbeat, 1000);
    }

    #[test]
    fn test_slash_oracle() {
        let (env, _, client) = setup();
        let oracle = Address::generate(&env);
        client.register_oracle(&oracle, &DEFAULT_MIN_STAKE);
        client.slash_oracle(&oracle, &5_000_000, &100);

        let provider = client.get_oracle(&oracle);
        assert_eq!(provider.stake, DEFAULT_MIN_STAKE - 5_000_000);
        assert_eq!(provider.reputation, DEFAULT_REP_INITIAL - 100);
    }

    // ── Feed Management ─────────────────────────────────────────────────

    #[test]
    fn test_create_feed() {
        let (env, _, client) = setup();
        let feed_id = create_test_feed(&env, &client);

        let feed = client.get_feed(&feed_id);
        assert_eq!(feed.feed_id, feed_id);
        assert!(feed.is_active);
        assert_eq!(feed.decimals, 8);
    }

    #[test]
    fn test_duplicate_feed_fails() {
        let (env, _, client) = setup();
        create_test_feed(&env, &client);
        let result = client.try_create_feed(
            &symbol_short!("XLMUSD"),
            &symbol_short!("XLM"),
            &symbol_short!("USD"),
            &8,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_update_feed() {
        let (env, _, client) = setup();
        let feed_id = create_test_feed(&env, &client);
        client.update_feed(&feed_id, &false, &7200, &5);

        let feed = client.get_feed(&feed_id);
        assert!(!feed.is_active);
        assert_eq!(feed.staleness_override_secs, 7200);
        assert_eq!(feed.min_oracles_override, 5);
    }

    // ── Full Price Round Lifecycle ──────────────────────────────────────

    #[test]
    fn test_full_price_round() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);
        let feed_id = create_test_feed(&env, &client);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        let round_id = client.open_round(&admin, &feed_id);
        assert_eq!(round_id, 1);

        // Submit prices
        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &100_500_000, &8500);
        client.submit_price(&oracles.get(2).unwrap(), &feed_id, &101_000_000, &9500);

        // Resolve
        let resolved = client.resolve_round(&admin, &feed_id);
        assert!(resolved.price > 0);
        assert_eq!(resolved.num_included, 3);
        assert_eq!(resolved.num_rejected, 0);
        assert_eq!(resolved.round_id, 1);

        // Query price
        let price = client.get_price(&feed_id);
        assert_eq!(price.price, resolved.price);
    }

    #[test]
    fn test_outlier_rejection() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 4);
        let feed_id = create_test_feed(&env, &client);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        // 3 close prices + 1 outlier
        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &100_100_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed_id, &100_200_000, &9000);
        client.submit_price(&oracles.get(3).unwrap(), &feed_id, &200_000_000, &5000); // outlier

        let resolved = client.resolve_round(&admin, &feed_id);
        assert_eq!(resolved.num_included, 3);
        assert_eq!(resolved.num_rejected, 1);

        // Outlier oracle should have reduced reputation
        let outlier_stats = client.get_oracle_stats(&oracles.get(3).unwrap());
        assert_eq!(outlier_stats.rejected_submissions, 1);
        assert!(outlier_stats.reputation < DEFAULT_REP_INITIAL);
    }

    #[test]
    fn test_reputation_reward() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);
        let feed_id = create_test_feed(&env, &client);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &100_100_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed_id, &100_200_000, &9000);

        client.resolve_round(&admin, &feed_id);

        // All oracles should have increased reputation
        for i in 0..3 {
            let stats = client.get_oracle_stats(&oracles.get(i).unwrap());
            assert_eq!(stats.reputation, DEFAULT_REP_INITIAL + DEFAULT_REP_REWARD);
            assert_eq!(stats.accepted_submissions, 1);
        }
    }

    #[test]
    fn test_missed_round_penalty() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 4);
        let feed_id = create_test_feed(&env, &client);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        // Only 3 of 4 oracles submit
        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &100_100_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed_id, &100_200_000, &9000);
        // Oracle 3 does NOT submit

        client.resolve_round(&admin, &feed_id);

        // Oracle 3 should be penalised for missing
        let stats = client.get_oracle_stats(&oracles.get(3).unwrap());
        assert_eq!(stats.missed_rounds, 1);
        assert_eq!(stats.reputation, DEFAULT_REP_INITIAL - DEFAULT_REP_MISS_PENALTY);
    }

    #[test]
    fn test_stale_price_detection() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);
        let feed_id = create_test_feed(&env, &client);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &100_100_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed_id, &100_200_000, &9000);

        client.resolve_round(&admin, &feed_id);

        // Fast-forward past staleness threshold
        env.ledger()
            .with_mut(|l| l.timestamp = 1000 + DEFAULT_STALENESS_SECS + 1);

        let result = client.try_get_price(&feed_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_insufficient_submissions() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 2); // only 2, need 3
        let feed_id = create_test_feed(&env, &client);

        // Lower min_oracles to allow round opening
        client.update_config(&1, &21, &300, &3600, &1500, &DEFAULT_MIN_STAKE, &600);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &100_100_000, &9000);

        // Restore min to 3, the feed uses network default
        client.update_config(&3, &21, &300, &3600, &1500, &DEFAULT_MIN_STAKE, &600);

        let result = client.try_resolve_round(&admin, &feed_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_submission_fails() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);
        let feed_id = create_test_feed(&env, &client);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        let result =
            client.try_submit_price(&oracles.get(0).unwrap(), &feed_id, &100_100_000, &9000);
        assert!(result.is_err());
    }

    #[test]
    fn test_submission_after_window_fails() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);
        let feed_id = create_test_feed(&env, &client);

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        // Move past submission window
        env.ledger()
            .with_mut(|l| l.timestamp = 1000 + DEFAULT_SUBMISSION_WINDOW_SECS + 1);

        let result =
            client.try_submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_rounds() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);
        let feed_id = create_test_feed(&env, &client);

        // Round 1
        env.ledger().with_mut(|l| l.timestamp = 1000);
        let r1 = client.open_round(&admin, &feed_id);
        assert_eq!(r1, 1);

        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &100_100_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed_id, &100_200_000, &9000);
        client.resolve_round(&admin, &feed_id);

        // Round 2
        env.ledger().with_mut(|l| l.timestamp = 2000);
        let r2 = client.open_round(&admin, &feed_id);
        assert_eq!(r2, 2);

        client.submit_price(&oracles.get(0).unwrap(), &feed_id, &105_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed_id, &105_100_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed_id, &105_200_000, &9000);
        let resolved = client.resolve_round(&admin, &feed_id);

        assert_eq!(resolved.round_id, 2);
        assert!(resolved.price > 100_000_000); // price moved up

        // History should have 2 entries
        let history = client.get_price_history(&feed_id);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_multiple_feeds() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);

        let feed1 = symbol_short!("XLMUSD");
        let feed2 = symbol_short!("BTCUSD");
        client.create_feed(&feed1, &symbol_short!("XLM"), &symbol_short!("USD"), &8);
        client.create_feed(&feed2, &symbol_short!("BTC"), &symbol_short!("USD"), &8);

        env.ledger().with_mut(|l| l.timestamp = 1000);

        // Round on both feeds
        client.open_round(&admin, &feed1);
        client.open_round(&admin, &feed2);

        client.submit_price(&oracles.get(0).unwrap(), &feed1, &100_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed1, &100_100_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed1, &100_200_000, &9000);

        client.submit_price(&oracles.get(0).unwrap(), &feed2, &50_000_00_000_000, &9000);
        client.submit_price(&oracles.get(1).unwrap(), &feed2, &50_100_00_000_000, &9000);
        client.submit_price(&oracles.get(2).unwrap(), &feed2, &50_200_00_000_000, &9000);

        let r1 = client.resolve_round(&admin, &feed1);
        let r2 = client.resolve_round(&admin, &feed2);

        assert!(r1.price > 0);
        assert!(r2.price > 0);
        assert_ne!(r1.price, r2.price);

        let feeds = client.list_feeds();
        assert_eq!(feeds.len(), 2);
    }

    #[test]
    fn test_pause_unpause() {
        let (env, admin, client) = setup();
        let oracle = Address::generate(&env);

        client.set_paused(&true);
        let result = client.try_register_oracle(&oracle, &DEFAULT_MIN_STAKE);
        assert!(result.is_err());

        client.set_paused(&false);
        client.register_oracle(&oracle, &DEFAULT_MIN_STAKE);
    }

    #[test]
    fn test_enforce_heartbeats() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);

        // Advance past heartbeat interval
        env.ledger()
            .with_mut(|l| l.timestamp = DEFAULT_HEARTBEAT_INTERVAL + 100);

        let deactivated = client.enforce_heartbeats();
        assert_eq!(deactivated, 3);

        // All should be inactive now
        for i in 0..3 {
            let provider = client.get_oracle(&oracles.get(i).unwrap());
            assert!(!provider.is_active);
        }
    }

    #[test]
    fn test_network_stats() {
        let (env, admin, client) = setup();
        let _oracles = register_oracles(&env, &client, 5);
        create_test_feed(&env, &client);

        let stats = client.get_network_stats();
        assert_eq!(stats.total_oracles, 5);
        assert_eq!(stats.active_oracles, 5);
        assert_eq!(stats.total_feeds, 1);
        assert_eq!(stats.active_feeds, 1);
    }

    #[test]
    fn test_oracle_list() {
        let (env, _, client) = setup();
        let oracles = register_oracles(&env, &client, 4);

        let list = client.list_oracles();
        assert_eq!(list.len(), 4);
    }

    #[test]
    fn test_weighted_median_basic() {
        let env = Env::default();
        let mut data: Vec<(i128, u32)> = Vec::new(&env);
        data.push_back((100, 10));
        data.push_back((200, 10));
        data.push_back((300, 10));

        let result = weighted_median(&env, &data);
        assert_eq!(result, 200); // equal weights → normal median
    }

    #[test]
    fn test_weighted_median_skewed() {
        let env = Env::default();
        let mut data: Vec<(i128, u32)> = Vec::new(&env);
        // High-rep oracle at 100, two low-rep at 200/300
        data.push_back((100, 100));
        data.push_back((200, 10));
        data.push_back((300, 10));

        let result = weighted_median(&env, &data);
        assert_eq!(result, 100); // 100's weight dominates
    }

    #[test]
    fn test_outlier_detection() {
        // 15% threshold (1500 bps)
        assert!(!is_outlier(100, 100, 1500)); // 0% deviation
        assert!(!is_outlier(110, 100, 1500)); // 10% deviation
        assert!(is_outlier(120, 100, 1500)); // 20% deviation
        assert!(is_outlier(200, 100, 1500)); // 100% deviation
        assert!(!is_outlier(85, 100, 1500)); // 15% deviation – boundary
    }

    #[test]
    fn test_inactive_oracle_cannot_submit() {
        let (env, admin, client) = setup();
        let oracles = register_oracles(&env, &client, 3);
        let feed_id = create_test_feed(&env, &client);

        client.deactivate_oracle(&oracles.get(0).unwrap());

        env.ledger().with_mut(|l| l.timestamp = 1000);
        client.open_round(&admin, &feed_id);

        let result =
            client.try_submit_price(&oracles.get(0).unwrap(), &feed_id, &100_000_000, &9000);
        assert!(result.is_err());
    }
}
