#![no_std]

use soroban_sdk::{contract, contractimpl};

mod contract;
mod storage;
mod types;
mod utils;

use contract::{DaoContract, DaoError};

#[contract]
pub struct Dao;

#[contractimpl]
impl Dao {
    /// Create a new governance proposal.
    ///
    /// # Arguments
    /// * `creator`         – Address of the proposal creator (must sign)
    /// * `title`           – Proposal title: 3–200 characters
    /// * `description`     – Proposal body: 1–2 048 characters
    /// * `voting_duration` – Voting window in seconds; must be 1 hour–30 days
    ///
    /// # Returns
    /// The sequential proposal ID, or a [`DaoError`] on invalid input.
    pub fn create_proposal(
        env: soroban_sdk::Env,
        creator: soroban_sdk::Address,
        title: soroban_sdk::String,
        description: soroban_sdk::String,
        voting_duration: u64,
    ) -> Result<u64, DaoError> {
        DaoContract::create_proposal(env, creator, title, description, voting_duration)
    }

    /// Cast a vote on a proposal.
    ///
    /// # Arguments
    /// * `proposal_id` – ID of the proposal to vote on
    /// * `voter`       – Address of the voter (must sign)
    /// * `choice`      – `VoteChoice::Yes` or `VoteChoice::No`
    ///
    /// # Returns
    /// `Ok(())` or a [`DaoError`] describing the failure.
    pub fn vote(
        env: soroban_sdk::Env,
        proposal_id: u64,
        voter: soroban_sdk::Address,
        choice: types::VoteChoice,
    ) -> Result<(), DaoError> {
        DaoContract::vote(env, proposal_id, voter, choice)
    }

    /// Fetch a proposal by its ID.
    ///
    /// # Returns
    /// `Ok(Proposal)` or `Err(DaoError::ProposalNotFound)`.
    pub fn get_proposal(
        env: soroban_sdk::Env,
        proposal_id: u64,
    ) -> Result<types::Proposal, DaoError> {
        DaoContract::get_proposal(env, proposal_id)
    }

    /// Return the total number of proposals created.
    pub fn proposal_count(env: soroban_sdk::Env) -> u64 {
        DaoContract::proposal_count(env)
    }
}
