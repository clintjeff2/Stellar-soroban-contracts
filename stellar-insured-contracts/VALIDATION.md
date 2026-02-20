# Input Validation & Sanitization Guide

This document describes the comprehensive input validation layer implemented
across all Stellar Insured contracts, addressing
**Issue \#29 – Add Comprehensive Input Validation and Sanitization**.

---

## Architecture

All validation logic is centralised in the **`shared`** crate at
`contracts/shared/src/validation.rs`. Other contracts import helpers from there
instead of duplicating logic. This guarantees:

- Consistent bounds across every contract.
- A single place to tighten a limit without hunting down every callsite.
- Uniform error codes that callers and front-ends can rely on.

---

## Error Code Ranges

| Range  | Category                |
|--------|-------------------------|
| 1–19   | General / Authorization |
| 20–39  | Policy                  |
| 40–59  | Claims                  |
| 60–79  | Oracle                  |
| 80–99  | Governance              |
| 100–119| Treasury                |
| 120–139| Slashing                |
| 140–159| Risk Pool               |
| 160–179| Cross-Chain             |
| **200–249** | **Input Validation (new)** |

New validation-specific codes (200–249):

| Code | Variant                | Meaning                                         |
|------|------------------------|-------------------------------------------------|
| 200  | `AmountMustBePositive` | Amount ≤ 0                                      |
| 201  | `AmountOutOfBounds`    | Amount outside [min, max]                       |
| 202  | `InvalidPercentage`    | Percentage > 100                                |
| 203  | `InvalidBasisPoints`   | Basis points > 10 000                           |
| 204  | `TimestampNotFuture`   | Timestamp ≤ current time                        |
| 205  | `TimestampNotPast`     | Timestamp > current time                        |
| 206  | `InvalidTimeRange`     | start ≥ end                                     |
| 207  | `EmptyInput`           | String/bytes length = 0                         |
| 208  | `InputTooLong`         | Input exceeds max allowed length                |
| 209  | `InputTooShort`        | Input below min required length                 |
| 210  | `InvalidPaginationParams` | limit = 0 or > 1 000                        |
| 211  | `DuplicateAddress`     | addr1 == addr2 when they must differ            |
| 212  | `QuorumTooLow`         | Quorum < 10 %                                   |
| 213  | `ThresholdTooLow`      | Approval threshold ≤ 50 %                       |

---

## Validation by Contract

### Policy Contract

| Parameter        | Validator                      | Allowed Range / Rule                 |
|------------------|-------------------------------|--------------------------------------|
| `coverage_amount`| `validate_coverage_amount`    | 1 XLM – 1 000 000 XLM               |
| `premium_amount` | `validate_premium_amount`     | 0.1 XLM – 100 000 XLM               |
| `duration_days`  | `validate_duration_days`      | 1 – 1 825 days                       |
| `holder`         | `validate_address`            | Valid Soroban address                 |
| Premium vs Coverage | `validate_policy_params`   | `premium < coverage` (sanity)        |

### Claims Contract

| Parameter             | Validator              | Allowed Range / Rule                |
|-----------------------|------------------------|--------------------------------------|
| `amount`              | `validate_amount`      | > 0                                 |
| `amount`              | Coverage constraint    | ≤ policy coverage amount            |
| `min_oracle_submissions` | In-line guard       | 1 – 100                             |
| `claimant`            | `validate_address`     | Valid Soroban address                |

Specific errors returned:
- `InvalidAmount` (103) — amount ≤ 0
- `CoverageExceeded` (105) — amount > coverage

### Risk Pool Contract

| Parameter           | Validator            | Allowed Range / Rule                     |
|---------------------|----------------------|------------------------------------------|
| `amount` (deposit)  | `validate_amount`    | > 0, ≤ 10 billion XLM                   |
| `min_provider_stake`| Range guard          | > 0, ≤ 1 billion XLM                    |
| Stake threshold     | Cumulative guard     | Deposit brings total ≥ min_stake         |
| `provider`          | `validate_address`   | Valid Soroban address                    |

### Governance Contract

| Parameter              | Validator / Guard       | Allowed Range / Rule                 |
|------------------------|-------------------------|--------------------------------------|
| `voting_period_days`   | Range guard             | 1 – 365 days                         |
| `min_voting_percentage`| Range guard             | 51 % – 100 % (must be > 50 %)        |
| `min_quorum_percentage`| Range guard             | 10 % – 100 %                         |
| `threshold_percentage` | Range guard             | 51 % – 100 %                         |
| `vote_weight`          | Range guard             | > 0, ≤ 10^18                         |
| `amount` (slashing)    | Range guard             | > 0, ≤ 10^15                         |

### DAO Proposal Contract

Uses a dedicated `DaoError` enum with typed variants:

| Parameter         | Validator              | Allowed Range / Rule                   |
|-------------------|------------------------|----------------------------------------|
| `title`           | `validate_title`       | 3 – 200 characters                     |
| `description`     | `validate_description` | 1 – 2 048 characters                   |
| `voting_duration` | `validate_voting_duration` | 3 600 s (1 h) – 2 592 000 s (30 d) |

All functions now return `Result<_, DaoError>` instead of panicking.

---

## Reusable Validation Functions

All functions live in `shared::validation` and can be called with `?` sugar:

```rust
use shared::validation::{
    validate_policy_params,
    validate_claim_params,
    validate_risk_pool_init_params,
    validate_proposal_params,
    validate_evidence_hash,
    validate_metadata,
    validate_description,
    validate_pagination,
    safe_add, safe_sub, safe_mul, safe_div,
};
```

### Address Validation
```rust
validate_address(&env, &holder)?;
validate_addresses_different(&sender, &recipient)?;
```

### Amount Validation
```rust
validate_positive_amount(amount)?;
validate_coverage_amount(coverage)?;
validate_premium_amount(premium)?;
validate_claim_amount(claim_amount, coverage_amount)?;
validate_deposit_amount(amount, min_stake)?;
validate_withdrawal_amount(amount, available_balance)?;
```

### Time Validation
```rust
validate_future_timestamp(env.ledger().timestamp(), expiry)?;
validate_duration_days(duration_days)?;
validate_voting_duration(voting_secs)?;
validate_time_range(start, end)?;
```

### String / Bytes Sanitization
```rust
validate_metadata(&metadata_string)?;      // ≤ 1024 chars
validate_description(&desc_string)?;       // ≤ 2048 chars
validate_proposal_title(&title_string)?;   // 3–200 chars
validate_evidence_hash(&hash_bytes)?;      // non-zero BytesN<32>
```

### Governance Validation
```rust
validate_quorum_percent(quorum)?;          // 10–100 %
validate_voting_threshold(threshold)?;     // 51–100 %
validate_basis_points(bps)?;              // 0–10 000
validate_reserve_ratio(ratio)?;            // 20–100 %
```

### Safe Arithmetic
```rust
let sum  = safe_add(a, b)?;  // Err(Overflow) on overflow
let diff = safe_sub(a, b)?;  // Err(Underflow) on underflow
let prod = safe_mul(a, b)?;  // Err(Overflow) on overflow
let quot = safe_div(a, b)?;  // Err(DivisionByZero) if b == 0
```

### Composite Validators (call these at the top of each function)
```rust
// Policy creation
validate_policy_params(&holder, coverage, premium, duration_days, &env)?;

// Claim submission
validate_claim_params(&claimant, claim_amount, coverage_amount, &env)?;

// Risk pool initialisation
validate_risk_pool_init_params(&admin, &token, min_stake, &env)?;

// Governance proposal
validate_proposal_params(&title, &description, voting_secs)?;
```

---

## Adding Validation to a New Function

1. **Identify all inputs** that arrive from external callers.
2. **Choose or add a validator** in `shared/src/validation.rs`.
3. **Choose or add an error code** in `shared/src/errors.rs` (range 200–249 for
   input validation).
4. **Call the validator with `?`** at the top of the function, before any
   storage reads or business logic.
5. **Write a test** that passes an invalid value and asserts the expected error.

---

## Acceptance Criteria Status

| Criterion                                                    | Status     |
|--------------------------------------------------------------|------------|
| All numeric inputs validated for reasonable ranges           | ✅ Done    |
| All address inputs validated for proper format               | ✅ Done    |
| All string inputs validated for length and content           | ✅ Done    |
| Clear error messages returned for validation failures        | ✅ Done    |
| Validation functions are reusable across contracts           | ✅ Done    |
| Centralised validation utilities in shared module            | ✅ Done    |
| Comprehensive error codes for validation failures            | ✅ Done    |
