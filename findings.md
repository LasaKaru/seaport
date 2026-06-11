# Seaport — Security & Code-Quality Audit Findings

**Repository:** `LasaKaru/seaport` (Seaport 1.6, Solidity 0.8.24, Foundry)
**Scope:** Full codebase — on-chain core protocol (`lib/seaport-core`) and off-chain
peripheral helpers (`contracts/helpers`).
**Date:** 2026-06-11

---

## Executive summary

The **on-chain core protocol** was audited across two independent passes (black-box
exploit probing and source-level white-box review of every assembly-heavy module).
**No exploitable on-chain vulnerability was found.** This is consistent with Seaport's
public audit history and its unclaimed bug bounty.

The **off-chain peripheral helper contracts** (`contracts/helpers/`), which are less
audited, contain **two confirmed logic bugs**, both reproduced with passing Foundry
PoCs, plus several minor/nit issues. Neither confirmed bug risks funds — these
contracts are read-only tooling used to pre-screen and classify orders, not part of
the on-chain settlement path. They do, however, cause the tooling to return incorrect
results, which can mislead integrators.

| # | Component | Issue | Severity | Funds at risk | PoC |
|---|-----------|-------|----------|---------------|-----|
| 1 | `SeaportValidator` | Offer-item balance/allowance check uses `min(start,end)` instead of `max` | Low (off-chain) | No | ✅ passing |
| 2 | `OrderStructureLib` (Navigator) | `_checkCriteria` early-return defeats "any item" semantics | Low (off-chain) | No | ✅ passing |
| 3 | `SeaportRouter` | `_returnExcessEther` re-reads balance in revert path | Minor | No | — |
| 4 | `SeaportValidator` | `AmountStepLarge` warning unrelated to step size | Minor | No | — |
| 5 | `CriteriaHelperLib` | `sortByHash` underflows on empty array (unreachable today) | Nit | No | — |
| 6 | `ArrayHelpers` | `indexOf` benign one-word OOB read on not-found path | Nit | No | — |
| 7 | `MerkleLib` | `verifyProof` / `log2ceil` dead code | Nit | No | — |

---

## Bug #1 — `SeaportValidator` under-checks offer-item balance & allowance

**File:** `contracts/helpers/order-validator/SeaportValidator.sol`
**Locations:** lines 873–876 (ERC1155), 913–917 (ERC20), 951–954 (native); same
pattern duplicated in `lib/SeaportValidatorHelper.sol`.
**Severity:** Low (off-chain validation helper; no on-chain fund risk).

### Description

`validateOfferItemApprovalAndBalance` computes the required balance/allowance for an
offer item as:

```solidity
// Get min required balance (max(startAmount, endAmount))
uint256 minBalance = offerItem.startAmount < offerItem.endAmount
    ? offerItem.startAmount   // <-- returns the SMALLER value
    : offerItem.endAmount;
```

There is a three-way contradiction:

- **Variable name:** `minBalance` / `minBalanceAndAllowance`
- **Comment:** `max(startAmount, endAmount)`
- **Actual computation:** `min(startAmount, endAmount)` (the `<` ternary selects the
  smaller operand)

For an offer item whose `startAmount != endAmount` (every Dutch-auction / ascending
order), the offerer must be able to deliver up to `max(start, end)` for the order to
be fillable across its **entire** lifetime. By validating against `min(start, end)`,
the validator returns a **false-clean** verdict for an offerer who can only cover the
cheapest point on the amount curve — silently missing `InsufficientBalance` /
`InsufficientAllowance` conditions it is specifically meant to surface. This affects
ERC1155, ERC20, and native offer items identically.

(The same inverted pattern exists in the upstream published validator, so this is a
long-standing latent bug rather than a newly introduced one.)

### Proof of Concept

`test/foundry/new/PoCValidatorMinMax.t.sol` — **2 passing tests.**

Construct a descending ERC20 offer (`startAmount = 100`, `endAmount = 10`;
`max = 100`, `min = 10`) and pin the enforced threshold:

- Offerer holding **10** (`== min`, far below the `100` the order may require) →
  validator reports **no** `InsufficientBalance`.
- Offerer holding **9** (`== min - 1`) → validator reports `InsufficientBalance`.

This pins the enforced threshold to exactly `min(start,end) = 10`, not the
`max(start,end) = 100` the comment promises.

```
[PASS] test_PoC1_holds_min_validatorSaysOk_butShouldFlag()
  BUG #1 confirmed: offerer holding only min(start,end)=10 of a max(start,end)=100 offer passes validation (false-clean).
[PASS] test_PoC1_holds_minMinusOne_validatorFlags()
  Threshold pinned: balance 9 flags, balance 10 passes => validator enforces min(start,end)=10, contradicting the 'max' comment.
```

### Suggested fix

Compute the maximum (worst-case) amount in all three offer-item branches (and the
mirror in `SeaportValidatorHelper.sol`):

```solidity
uint256 minBalance = offerItem.startAmount > offerItem.endAmount
    ? offerItem.startAmount
    : offerItem.endAmount;
```

and rename the variable to reflect that it is the worst-case required amount.

---

## Bug #2 — `OrderStructureLib._checkCriteria` early-return misclassifies orders

**File:** `contracts/helpers/navigator/lib/OrderStructureLib.sol`
**Location:** lines 485–518 (consumed by `getStructure`, lines 187–201).
**Severity:** Low (off-chain Navigator helper; affects suggested-action classification
only).

### Description

The docstring states `hasNonzeroCriteria` is "Whether **any** offer or consideration
item has nonzero criteria." The implementation `return`s on the **first**
criteria-bearing item it finds:

```solidity
if (hasCriteria) {
    return (hasCriteria, offerItem.identifierOrCriteria != 0);
}
```

so `hasNonzeroCriteria` reflects only the first criteria item, not an OR across all of
them. `getStructure` uses this for CONTRACT orders:

```solidity
if (hasCriteria) {
    if (isContractOrder) {
        if (hasNonzeroCriteria) return Structure.ADVANCED;
    } else {
        return Structure.ADVANCED;
    }
}
```

**Consequence:** a CONTRACT order whose **first** criteria item is a wildcard
(`identifierOrCriteria == 0`) but a **later** criteria item is nonzero is
misclassified as `STANDARD` instead of `ADVANCED`. A consumer relying on the Navigator
to decide how to fulfill the order (e.g. whether to supply criteria resolvers) would
be given the wrong structure and could build an unfulfillable call.

### Proof of Concept

`test/foundry/new/PoCNavigatorCriteria.t.sol` — **1 passing test.**

Two CONTRACT orders with **identical item content**, differing only in the **order**
of the two criteria items:

- **Order A:** `[ ERC721_WITH_CRITERIA(criteria=999), ERC1155_WITH_CRITERIA(criteria=0) ]`
  → classified `ADVANCED` (correct).
- **Order B:** `[ ERC1155_WITH_CRITERIA(criteria=0), ERC721_WITH_CRITERIA(criteria=999) ]`
  → classified `STANDARD` (**bug** — should be `ADVANCED`).

```
[PASS] test_PoC2_criteriaOrderingChangesStructure()
  Order A structure (0=BASIC,1=STANDARD,2=ADVANCED): 2
  Order B structure (0=BASIC,1=STANDARD,2=ADVANCED): 1
  BUG #2 confirmed: reordering identical criteria items flips a CONTRACT order between ADVANCED and STANDARD.
```

Classification depends purely on item ordering, which it must not.

### Suggested fix

Scan all items and OR the nonzero flags instead of early-returning:

```solidity
function _checkCriteria(AdvancedOrder memory order)
    internal pure returns (bool hasCriteria, bool hasNonzeroCriteria)
{
    OfferItem[] memory offer = order.parameters.offer;
    for (uint256 i; i < offer.length; ++i) {
        ItemType itemType = offer[i].itemType;
        if (itemType == ItemType.ERC721_WITH_CRITERIA ||
            itemType == ItemType.ERC1155_WITH_CRITERIA) {
            hasCriteria = true;
            if (offer[i].identifierOrCriteria != 0) hasNonzeroCriteria = true;
        }
    }
    ConsiderationItem[] memory consideration = order.parameters.consideration;
    for (uint256 i; i < consideration.length; ++i) {
        ItemType itemType = consideration[i].itemType;
        if (itemType == ItemType.ERC721_WITH_CRITERIA ||
            itemType == ItemType.ERC1155_WITH_CRITERIA) {
            hasCriteria = true;
            if (consideration[i].identifierOrCriteria != 0) hasNonzeroCriteria = true;
        }
    }
}
```

---

## Lower-severity findings

### #3 — `SeaportRouter._returnExcessEther` re-reads balance in revert path
`contracts/helpers/SeaportRouter.sol:243-254` (and the identical
`lib/seaport-core/src/helpers/SeaportRouter.sol`). On a failed refund `call`, the
`EtherReturnTransferFailed` error reports `address(this).balance` evaluated **after**
the call rather than the attempted amount. It happens to be correct today (the failed
call returns false without moving ETH) but is fragile and misleading. Cache the amount
before the `call` and report the cached value.

### #4 — `AmountStepLarge` warning unrelated to step size
`SeaportValidator.sol:687-692` / `SeaportValidatorHelper.sol:370-375`. The warning
fires whenever `minAmount <= 1e15`, which has no relationship to the amount **step**
(delta) the warning name implies. Either the comment is stale or the condition is
wrong. Warning-only; no functional impact.

### #5 — `CriteriaHelperLib.sortByHash` empty-array underflow
`CriteriaHelperLib.sol:89`. `_quickSort(toSort, 0, int256(toSort.length - 1))`
underflows (and reverts under 0.8 checked arithmetic) when `toSort.length == 0`. The
only in-repo callers guard `length == 0`/`1` first, so it is unreachable today, but the
`internal` helpers offer no guard of their own.

### #6 — `ArrayHelpers.indexOf` one-word OOB read on not-found path
`contracts/helpers/ArrayHelpers.sol`. On the not-found path the routine reads one word
past the array before masking the result to `-1`. Benign (the value is discarded), but
a latent out-of-bounds memory read.

### #7 — `MerkleLib` dead code
`contracts/helpers/navigator/lib/MerkleLib.sol:52` (`verifyProof`) and `:164`
(`log2ceil`) are unused in the repo (carried over from the upstream Murky library);
`log2ceil` is also a slower duplicate of `log2ceilBitMagic`.

---

## On-chain core protocol — audited, no findings

Two full audit passes over the on-chain core produced **no exploitable
vulnerability.** Coverage included:

- **Partial-fill fraction math** (`OrderValidator`, `AmountDeriver`): rounding
  direction is fixed per item category (offer rounds down, consideration rounds up);
  fractional fills are exact-or-revert (`InexactFraction`); operands are 120-bit
  masked so cross-multiplications cannot wrap; the Euclidean GCD reduction is
  strictly-decreasing and guarded by `safeScaleDown` and a post-reduction `Panic`
  re-check; no dust/overfill path exists.
- **Fulfillment aggregation & execution** (`FulfillmentApplier`, `Executor`,
  `OrderCombiner`): aggregation keys are full-word keccak hashes (no ERC721/1155
  itemType aliasing); match reconciliation is backstopped by the
  `_revertConsiderationNotMet` zero-residual check; the conduit accumulator is an
  unbounded contiguous region with synchronized length; native refund is the
  post-execution residue sent only to `msg.sender`; consumed amounts are zeroed at
  consumption.
- **Criteria & signatures** (`CriteriaResolution`, `SignatureVerification`,
  `Verifiers`, `GettersAndDerivers`): merkle leaves are pre-hashed (32-byte vs 64-byte
  node domain separation); the EIP-1271 magic-value check is a full 32-byte word
  compare against pre-zeroed scratch with a one-word-capped return copy; bulk-order
  height is provably bounded to 1..24 and the typehash lookup is branchless (no OOB);
  EIP-2098 compact-sig handling has no `s`/`v` fall-through.
- **Zone authorize/validate lifecycle** (new in 1.6) (`ZoneInteraction`,
  `OrderCombiner`, `ConsiderationEncoder`): `authorizeOrder` runs strictly before any
  transfer under a held reentrancy guard; the orderHash passed to the zone is bound to
  the transferred items via EIP-712 + signature; the skip-vs-revert asymmetry is
  correct and the "authorized-then-skipped" gap is closed by `_revertOnFailedUpdate`.
- **Reentrancy guard & contract offerer** (`ReentrancyGuard`, `OrderFulfiller`,
  `ConsiderationDecoder`): the guard spans the full generateOrder → transfer →
  ratify window on every token-moving entrypoint; `generateOrder` amount/length
  comparisons are uniformly oriented in the counterparty's favor; the returndata
  decoder's `0xffff` length cap plus dual end-offset checks prevent out-of-range
  copies (independently re-verified with an adversarial `EvilReturndataOfferer` that
  returns raw attacker-chosen bytes — see `test/foundry/PoCDecoderVerify.t.sol`).

Combined with the prior probe/mutation/fuzz work (80+ attack probes, mutation tests,
25,000+ fuzz runs), the on-chain protocol is robust.

---

## Targeted high/critical hunt — value-extraction PoCs (no finding)

A dedicated pass attempted to extract real value on-chain across the three surfaces
where a high/critical Seaport bug would most plausibly live. Each hypothesis was
driven to a runnable Foundry test measuring before/after balance **deltas** (not
absolute balances, since the harness pre-funds accounts). Every attempt either
reverted or netted zero. The scratch exploit tests were removed after the
conclusions were recorded here; the defenses they probed are summarized below.

### Native ETH / `msg.value` accounting — DEFENDED (one known non-issue)
- **Pure `msg.value` double-count** across two native-consideration orders from an
  empty contract: reverts with `InsufficientNativeTokensSupplied`
  (`OrderCombiner.sol:849-852`). The per-execution `gt(amount, selfbalance())` guard
  stops it. DEFENDED.
- **Native-offer match cycle:** native offer items in a signed FULL_OPEN order are
  rejected by the match path. Reverts, zero delta. DEFENDED.
- **Sweep of resident ETH** via the end-of-call `selfbalance()` refund
  (`OrderCombiner.sol:987-999`): real behavior, but **not a vulnerability**. ETH only
  resides in Seaport if force-fed via `selfdestruct` (the attacker must irrevocably
  destroy their own ETH to place it there) — there is no victim, no profit, and no
  primitive to drain ETH from an empty contract or from other users. Seaport holds
  zero ETH between transactions by design (the refund sweep guarantees it). This is
  the same documented, out-of-scope class as the prior L1 finding.

### Multi-order fulfillment aggregation — DEFENDED (all 4 hypotheses)
- **Double-spend one offer item** toward two consideration obligations: second
  fulfillment re-reads the zeroed amount and reverts `MissingItemAmount`
  (offer amount zeroed at `FulfillmentApplier.sol:400`).
- **Consideration key collision, different recipients:** recipient is part of the
  aggregation hash (`FulfillmentApplier.sol:732`), so it reverts
  `InvalidFulfillmentComponentData`.
- **ERC721/ERC1155 same-id collision:** `itemType` is part of the offer aggregation
  hash (`FulfillmentApplier.sol:413`), so distinct types cannot be summed.
- **Receive offer without paying** (empty consideration group): reverts
  `MissingFulfillmentComponentOnAggregation`, backstopped by `_revertConsiderationNotMet`
  (`OrderCombiner.sol:959-961`).
- All produced zero positive attacker delta.

### Reentrancy / callback state confusion — DEFENDED (all 4 hypotheses)
- **ERC1155 receiver re-enters** to fulfill a second order mid-flight: re-entrant
  `fulfillOrder` reverts `NoReentrantCalls` (transient-storage guard armed until
  `OrderCombiner.sol:1024`). No extra item stolen.
- **Read-only reentrancy:** the view getters `getOrderStatus`/`getCounter` are
  reachable during a callback (unguarded by design), so mid-flight state *can be
  observed* — but no state-mutating path is reachable while the guard is armed, so the
  observation cannot be converted into value loss inside Seaport. (Worth noting for
  integrators who build logic on Seaport getters; not a Seaport-side bug.)
- **Contract offerer shorts the fulfiller:** yanking its own approval during
  `generateOrder` makes the offer transfer fail and the whole fill reverts atomically —
  fulfiller pays nothing, receives nothing. DEFENDED.
- **ERC777-style transfer-hook token** re-entering to double-fulfill: guard is set
  before any transfer, so the hook's re-entrant call reverts; order fills exactly once.

### Tip / `additionalRecipients` mechanism — DEFENDED
The order hash is recomputed from the first `totalOriginalConsiderationItems` items of
the *supplied* consideration array (`Assertions.sol:79-94`, `GettersAndDerivers.sol:74`),
and the supplied length must be ≥ original (`Assertions.sol:106-114`). A fulfiller can
only *append* trailing tip items they pay for themselves; dropping, reducing,
reordering, or altering any signed consideration item changes the derived hash and
fails signature verification. No "buyer pays less than the seller signed" path.

**Conclusion:** no high/critical on-chain vulnerability was found. The only confirmed
defects remain the two low-severity off-chain helper bugs (#1, #2 above).

## Reproducing the PoCs

```bash
forge test --match-path "test/foundry/new/PoCValidatorMinMax.t.sol"   -vv
forge test --match-path "test/foundry/new/PoCNavigatorCriteria.t.sol" -vv
```

Both suites pass, demonstrating the two confirmed off-chain bugs.
