//! Shared library for Stellar Insured Soroban contracts
//!
//! This module contains common types, utilities, and error handling
//! used across all insurance contracts in the Stellar Insured ecosystem.

use soroban_sdk::{contracttype, Address, Env, Symbol, String};

/// Re-export authorization module for easy access
/// Import authorization functions like: use insurance_contracts::authorization::*;
pub mod authorization {
    pub use authorization::{
        Role, RoleKey, AuthError,
        initialize_admin, get_admin, grant_role, revoke_role, get_role,
        has_role, require_role, require_admin, has_any_role, require_any_role,
        require_policy_management, require_claim_processing,
        require_risk_pool_management, require_governance_permission,
        register_trusted_contract, unregister_trusted_contract,
        is_trusted_contract, require_trusted_contract,
        verify_and_require_role, verify_and_check_permission,
    };
}

/// Common contract types shared across all insurance contracts
pub mod types {
    use super::*;

    /// Policy status enumeration
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum PolicyStatus {
        Active,
        Expired,
        Cancelled,
        Claimed,
    }

    /// Claim status enumeration
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ClaimStatus {
        Submitted,
        UnderReview,
        Approved,
        Rejected,
        Settled,
    }

    /// Governance proposal status
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ProposalStatus {
        Active,
        Passed,
        Rejected,
        Executed,
    }

    /// Vote type for governance
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum VoteType {
        Yes,
        No,
    }

    /// Common data key for contract storage
    #[contracttype]
    #[derive(Clone, Debug)]
    pub enum DataKey {
        Admin,
        Paused,
        Config,
        Counter(Symbol),
    }
}

/// Common error types for insurance contracts
pub mod errors {
    use soroban_sdk::{contracterror, Error};

    #[contracterror]
    #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub enum ContractError {
        /// Unauthorized access
        Unauthorized = 1,
        /// Contract is paused
        Paused = 2,
        /// Invalid input parameters
        InvalidInput = 3,
        /// Insufficient funds
        InsufficientFunds = 4,
        /// Item not found
        NotFound = 5,
        /// Item already exists
        AlreadyExists = 6,
        /// Invalid state transition
        InvalidState = 7,
        /// Arithmetic overflow
        Overflow = 8,
        /// Contract not initialized
        NotInitialized = 9,
        /// Already initialized
        AlreadyInitialized = 10,
        /// Invalid role or permission
        InvalidRole = 11,
        /// Role not found
        RoleNotFound = 12,
        /// Contract not trusted for cross-contract calls
        NotTrustedContract = 13,
    }
    
    /// Convert authorization errors to contract errors
    impl From<super::authorization::AuthError> for ContractError {
        fn from(err: super::authorization::AuthError) -> Self {
            match err {
                super::authorization::AuthError::Unauthorized => ContractError::Unauthorized,
                super::authorization::AuthError::InvalidRole => ContractError::InvalidRole,
                super::authorization::AuthError::RoleNotFound => ContractError::RoleNotFound,
                super::authorization::AuthError::NotTrustedContract => ContractError::NotTrustedContract,
            }
        }
    }
}

/// Utility functions for contract operations
pub mod utils {
    use super::*;
    use crate::errors::ContractError;
    use soroban_sdk::Vec;

    /// Validate that an address is valid (all Soroban addresses are valid by construction)
    pub fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
        Ok(())
    }

    /// Check if contract is paused
    pub fn is_paused(env: &Env) -> bool {
        env.storage()
            .persistent()
            .get(&crate::types::DataKey::Paused)
            .unwrap_or(false)
    }

    /// Set contract pause status (admin only)
    pub fn set_paused(env: &Env, paused: bool) {
        env.storage()
            .persistent()
            .set(&crate::types::DataKey::Paused, &paused);
    }

    /// Get next ID for a given counter
    pub fn next_id(env: &Env, counter_name: &str) -> u64 {
        let key = crate::types::DataKey::Counter(Symbol::new(env, counter_name));
        let current_id = env.storage().persistent().get(&key).unwrap_or(0u64);
        let next_id = current_id + 1;
        env.storage().persistent().set(&key, &next_id);
        next_id
    }

    /// Create a simple event log entry
    pub fn log_event(env: &Env, event_type: &str, data: Vec<String>) {
        env.events().publish((event_type, ()), data);
    }
}
