use soroban_sdk::{Env, Address, String};

use crate::storage::DataKey;
use crate::types::{Proposal, VoteChoice};
use crate::utils::current_time;

// ── Validation Constants ──────────────────────────────────────────────────────

/// Minimum number of characters for a proposal title.
const MIN_TITLE_LEN: u32 = 3;
/// Maximum number of characters for a proposal title.
const MAX_TITLE_LEN: u32 = 200;
/// Maximum number of characters for a proposal description.
const MAX_DESCRIPTION_LEN: u32 = 2_048;
/// Minimum voting duration in seconds (1 hour).
const MIN_VOTING_DURATION_SECS: u64 = 3_600;
/// Maximum voting duration in seconds (30 days).
const MAX_VOTING_DURATION_SECS: u64 = 30 * 86_400;

// ── Domain Errors ─────────────────────────────────────────────────────────────

/// Error type for DAO proposal operations.
///
/// All variants carry a unique numeric code so client code can match on the
/// integer returned by the Soroban host without depending on the SDK enum.
#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DaoError {
    /// Proposal was not found in storage.
    ProposalNotFound = 1,
    /// The voting period has already closed.
    VotingClosed = 2,
    /// The caller has already submitted a vote for this proposal.
    AlreadyVoted = 3,
    /// The proposal title is empty or outside allowed length bounds.
    InvalidTitle = 4,
    /// The proposal description is outside the allowed length bounds.
    InvalidDescription = 5,
    /// The voting duration is outside the allowed range [1 hour, 30 days].
    InvalidVotingDuration = 6,
    /// The contract is paused.
    Paused = 7,
}

// ── Validation Helpers ────────────────────────────────────────────────────────

/// Validate that a proposal title is non-empty and within allowed length.
fn validate_title(title: &String) -> Result<(), DaoError> {
    if title.len() < MIN_TITLE_LEN {
        return Err(DaoError::InvalidTitle);
    }
    if title.len() > MAX_TITLE_LEN {
        return Err(DaoError::InvalidTitle);
    }
    Ok(())
}

/// Validate that a proposal description is non-empty and within allowed length.
fn validate_description(description: &String) -> Result<(), DaoError> {
    if description.len() == 0 {
        return Err(DaoError::InvalidDescription);
    }
    if description.len() > MAX_DESCRIPTION_LEN {
        return Err(DaoError::InvalidDescription);
    }
    Ok(())
}

/// Validate that the voting duration is within the allowed range.
fn validate_voting_duration(duration_secs: u64) -> Result<(), DaoError> {
    if duration_secs < MIN_VOTING_DURATION_SECS || duration_secs > MAX_VOTING_DURATION_SECS {
        return Err(DaoError::InvalidVotingDuration);
    }
    Ok(())
}

// ── Contract Implementation ───────────────────────────────────────────────────

pub struct DaoContract;

impl DaoContract {
    // ── Proposal Creation ─────────────────────────────────────────────────

    /// Create a new governance proposal.
    ///
    /// # Validation
    /// - `title`: 3–200 characters
    /// - `description`: 1–2 048 characters
    /// - `voting_duration`: 1 hour–30 days (in seconds)
    ///
    /// # Returns
    /// The newly assigned proposal ID, or a [`DaoError`] on invalid input.
    pub fn create_proposal(
        env: Env,
        creator: Address,
        title: String,
        description: String,
        voting_duration: u64,
    ) -> Result<u64, DaoError> {
        creator.require_auth();

        // ── Input Validation ──────────────────────────────────────────────
        validate_title(&title)?;
        validate_description(&description)?;
        validate_voting_duration(voting_duration)?;
        // ─────────────────────────────────────────────────────────────────

        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .unwrap_or(0u64);

        let now = current_time(&env);

        let proposal = Proposal {
            id,
            creator,
            title,
            description,
            start_time: now,
            end_time: now
                .checked_add(voting_duration)
                .unwrap_or(u64::MAX), // overflow-safe
            yes_votes: 0,
            no_votes: 0,
            executed: false,
        };

        env.storage()
            .instance()
            .set(&DataKey::Proposal(id), &proposal);

        env.storage()
            .instance()
            .set(&DataKey::ProposalCount, &(id + 1));

        Ok(id)
    }

    // ── Voting ────────────────────────────────────────────────────────────

    /// Cast a vote on an existing proposal.
    ///
    /// # Validation
    /// - The proposal must exist.
    /// - The voting window (`start_time`..`end_time`) must be active.
    /// - The caller must not have voted before.
    ///
    /// # Returns
    /// `Ok(())` on success, or a [`DaoError`] describing the problem.
    pub fn vote(
        env: Env,
        proposal_id: u64,
        voter: Address,
        choice: VoteChoice,
    ) -> Result<(), DaoError> {
        voter.require_auth();

        // ── Fetch & Validate Proposal ─────────────────────────────────────
        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(DaoError::ProposalNotFound)?;

        let now = current_time(&env);

        if now < proposal.start_time || now > proposal.end_time {
            return Err(DaoError::VotingClosed);
        }

        let vote_key = DataKey::Vote(proposal_id, voter.clone());

        if env.storage().instance().has(&vote_key) {
            return Err(DaoError::AlreadyVoted);
        }
        // ─────────────────────────────────────────────────────────────────

        match choice {
            VoteChoice::Yes => proposal.yes_votes += 1,
            VoteChoice::No => proposal.no_votes += 1,
        }

        env.storage().instance().set(&vote_key, &choice);
        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        Ok(())
    }

    // ── Read-only Queries ─────────────────────────────────────────────────

    /// Retrieve a proposal by its ID.
    ///
    /// # Returns
    /// `Ok(Proposal)` if found, `Err(DaoError::ProposalNotFound)` otherwise.
    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<Proposal, DaoError> {
        env.storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(DaoError::ProposalNotFound)
    }

    /// Return the total number of proposals created so far.
    pub fn proposal_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .unwrap_or(0u64)
    }
}
