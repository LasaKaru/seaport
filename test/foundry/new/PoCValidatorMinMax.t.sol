// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * PoC for BUG #1 — SeaportValidator under-checks offer-item balance/allowance.
 *
 * SeaportValidator.validateOfferItemApprovalAndBalance computes the required
 * balance/allowance for an offer item as:
 *
 *     // Get min required balance (max(startAmount, endAmount))
 *     uint256 minBalance = offerItem.startAmount < offerItem.endAmount
 *         ? offerItem.startAmount      //  <-- returns the SMALLER value
 *         : offerItem.endAmount;
 *
 * The comment says max(start,end); the code returns min(start,end). For any
 * order whose start and end amounts differ (every Dutch / ascending order),
 * the offerer must be able to deliver up to max(start,end) for the order to be
 * fillable across its whole lifetime. By checking only min(start,end) the
 * validator returns a false-clean verdict for an offerer who can cover only the
 * cheapest point on the amount curve.
 *
 * This test PROVES the threshold the validator actually enforces is
 * min(start,end), not max(start,end):
 *
 *   - offerItem startAmount = 100, endAmount = 10  ->  max = 100, min = 10
 *   - offerer holding 10 (== min)  -> validator reports NO InsufficientBalance
 *   - offerer holding 9  (== min-1)-> validator reports InsufficientBalance
 *
 * If the validator obeyed its own comment (max = 100) the 10-token holder would
 * be flagged. It is not — demonstrating the bug.
 */

import {
    ErrorsAndWarnings,
    ERC20Issue,
    IssueParser,
    SeaportValidator
} from "../../../contracts/helpers/order-validator/SeaportValidator.sol";

import {
    OfferItemLib,
    OrderParametersLib,
    ItemType,
    OrderType
} from "seaport-sol/src/SeaportSol.sol";

import {
    OfferItem,
    OrderParameters
} from "seaport-sol/src/SeaportStructs.sol";

import { BaseOrderTest } from "./BaseOrderTest.sol";
import { SeaportValidatorTest } from "./SeaportValidatorTest.sol";

contract PoCValidatorMinMax is BaseOrderTest, SeaportValidatorTest {
    using OfferItemLib for OfferItem;
    using OrderParametersLib for OrderParameters;
    using IssueParser for ERC20Issue;

    uint16 constant INSUFFICIENT_BALANCE = 203; // ERC20Issue.InsufficientBalance
    uint16 constant INSUFFICIENT_ALLOWANCE = 202; // ERC20Issue.InsufficientAllowance

    function setUp() public override(BaseOrderTest, SeaportValidatorTest) {
        super.setUp();
    }

    function _hasError(
        ErrorsAndWarnings memory ew,
        uint16 code
    ) internal pure returns (bool) {
        for (uint256 i; i < ew.errors.length; ++i) {
            if (ew.errors[i] == code) return true;
        }
        return false;
    }

    // Build a descending ERC20 offer: startAmount=100, endAmount=10.
    // conduitKey 0 => approval target is Seaport itself.
    function _descendingErc20Order(
        address offerer
    ) internal view returns (OrderParameters memory params) {
        OfferItem[] memory offer = new OfferItem[](1);
        offer[0] = OfferItemLib
            .empty()
            .withItemType(ItemType.ERC20)
            .withToken(address(erc20s[0]))
            .withIdentifierOrCriteria(0)
            .withStartAmount(100)
            .withEndAmount(10);

        params = OrderParametersLib
            .empty()
            .withOfferer(offerer)
            .withOrderType(OrderType.FULL_OPEN)
            .withConduitKey(bytes32(0))
            .withOffer(offer);
    }

    // ---- The order requires up to 100 tokens; offerer holds exactly 10. ----
    // Buggy validator: NO InsufficientBalance (threshold pinned to min=10).
    function test_PoC1_holds_min_validatorSaysOk_butShouldFlag() public {
        address victim = makeAddr("descending offerer (holds min)");
        erc20s[0].mint(victim, 10); // == min(start,end); < max(start,end)=100
        vm.prank(victim);
        erc20s[0].approve(address(seaport), type(uint256).max);

        OrderParameters memory params = _descendingErc20Order(victim);

        ErrorsAndWarnings memory ew = validator
            .validateOfferItemApprovalAndBalance(params, 0, address(seaport));

        // Allowance is max, so no allowance error — isolates the balance check.
        assertFalse(
            _hasError(ew, INSUFFICIENT_ALLOWANCE),
            "allowance should be fine (approved max)"
        );

        // BUG: validator reports the order as balance-OK even though the order
        // requires up to 100 tokens at its start and the offerer holds only 10.
        assertFalse(
            _hasError(ew, INSUFFICIENT_BALANCE),
            "PoC FAILED to reproduce: validator unexpectedly flagged balance"
        );

        emit log(
            "BUG #1 confirmed: offerer holding only min(start,end)=10 of a "
            "max(start,end)=100 offer passes validation (false-clean)."
        );
    }

    // ---- Pin the threshold to min: balance = min-1 = 9 DOES error. ----
    // Together with the test above this proves the enforced threshold is
    // exactly min(start,end)=10, not max(start,end)=100.
    function test_PoC1_holds_minMinusOne_validatorFlags() public {
        address victim = makeAddr("descending offerer (holds min-1)");
        erc20s[0].mint(victim, 9); // == min-1
        vm.prank(victim);
        erc20s[0].approve(address(seaport), type(uint256).max);

        OrderParameters memory params = _descendingErc20Order(victim);

        ErrorsAndWarnings memory ew = validator
            .validateOfferItemApprovalAndBalance(params, 0, address(seaport));

        assertTrue(
            _hasError(ew, INSUFFICIENT_BALANCE),
            "balance below min should be flagged"
        );

        emit log(
            "Threshold pinned: balance 9 flags, balance 10 passes => "
            "validator enforces min(start,end)=10, contradicting the 'max' comment."
        );
    }
}
