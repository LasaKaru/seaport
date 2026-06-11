// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * PoC for BUG #2 — OrderStructureLib._checkCriteria early-return.
 *
 * The docstring states hasNonzeroCriteria is "Whether ANY offer or
 * consideration item has nonzero criteria." The implementation, however,
 * RETURNS on the first criteria-bearing item it encounters:
 *
 *     if (hasCriteria) {
 *         return (hasCriteria, offerItem.identifierOrCriteria != 0);
 *     }
 *
 * so hasNonzeroCriteria reflects only the FIRST criteria item, not an OR across
 * all of them. getStructure (used by SeaportNavigator to advise callers how to
 * fulfill an order) consumes this for CONTRACT orders:
 *
 *     if (hasCriteria) {
 *         if (isContractOrder) {
 *             if (hasNonzeroCriteria) return Structure.ADVANCED;
 *         } else { return Structure.ADVANCED; }
 *     }
 *
 * Consequence: a CONTRACT order whose FIRST criteria item is a wildcard
 * (identifierOrCriteria == 0) but a LATER criteria item is nonzero is
 * misclassified as STANDARD instead of ADVANCED.
 *
 * This PoC builds two contract orders with IDENTICAL item content that differ
 * only in the ORDER of the two criteria items, and shows getStructure returns
 * different structures — proving the classification depends on item ordering,
 * which it must not.
 */

import { Test } from "forge-std/Test.sol";

import {
    OrderStructureLib,
    Structure
} from "../../../contracts/helpers/navigator/lib/OrderStructureLib.sol";

import {
    OfferItemLib,
    OrderParametersLib,
    AdvancedOrderLib,
    ItemType,
    OrderType
} from "seaport-sol/src/SeaportSol.sol";

import {
    OfferItem,
    OrderParameters,
    AdvancedOrder
} from "seaport-sol/src/SeaportStructs.sol";

contract PoCNavigatorCriteria is Test {
    using OfferItemLib for OfferItem;
    using OrderParametersLib for OrderParameters;
    using AdvancedOrderLib for AdvancedOrder;
    using OrderStructureLib for AdvancedOrder;

    // seaport address is irrelevant for CONTRACT orders: getBasicOrderTypeEligibility
    // returns false before touching it. Use a dummy.
    address constant SEAPORT = address(0x5EA);

    function _criteriaItem(
        ItemType itemType,
        uint256 criteria
    ) internal pure returns (OfferItem memory) {
        return
            OfferItemLib
                .empty()
                .withItemType(itemType)
                .withToken(address(0xCAFE))
                .withIdentifierOrCriteria(criteria)
                .withStartAmount(1)
                .withEndAmount(1);
    }

    function _contractOrder(
        OfferItem[] memory offer
    ) internal pure returns (AdvancedOrder memory) {
        OrderParameters memory params = OrderParametersLib
            .empty()
            .withOrderType(OrderType.CONTRACT)
            .withOffer(offer);

        return
            AdvancedOrderLib
                .empty()
                .withParameters(params)
                .withNumerator(1)
                .withDenominator(1);
    }

    function test_PoC2_criteriaOrderingChangesStructure() public {
        // Order A: nonzero-criteria item FIRST, wildcard SECOND.
        OfferItem[] memory offerA = new OfferItem[](2);
        offerA[0] = _criteriaItem(ItemType.ERC721_WITH_CRITERIA, 999); // nonzero
        offerA[1] = _criteriaItem(ItemType.ERC1155_WITH_CRITERIA, 0); // wildcard
        AdvancedOrder memory orderA = _contractOrder(offerA);

        // Order B: SAME items, reversed — wildcard FIRST, nonzero SECOND.
        OfferItem[] memory offerB = new OfferItem[](2);
        offerB[0] = _criteriaItem(ItemType.ERC1155_WITH_CRITERIA, 0); // wildcard
        offerB[1] = _criteriaItem(ItemType.ERC721_WITH_CRITERIA, 999); // nonzero
        AdvancedOrder memory orderB = _contractOrder(offerB);

        Structure structA = OrderStructureLib.getStructure(orderA, SEAPORT);
        Structure structB = OrderStructureLib.getStructure(orderB, SEAPORT);

        emit log_named_uint("Order A structure (0=BASIC,1=STANDARD,2=ADVANCED)", uint256(structA));
        emit log_named_uint("Order B structure (0=BASIC,1=STANDARD,2=ADVANCED)", uint256(structB));

        // Order A: first criteria item is nonzero -> correctly ADVANCED.
        assertEq(uint256(structA), uint256(Structure.ADVANCED), "A should be ADVANCED");

        // Order B SHOULD also be ADVANCED (it has a nonzero-criteria item), but
        // the early-return bug only inspects the FIRST (wildcard) item and
        // classifies it STANDARD. This assertion documents the buggy output.
        assertEq(uint256(structB), uint256(Structure.STANDARD), "B observed as STANDARD (BUG)");

        // The smoking gun: identical item content, classification differs purely
        // by ordering. A correct _checkCriteria (OR across all items) would make
        // both ADVANCED and this inequality would not hold.
        assertTrue(structA != structB, "BUG #2: structure depends on item ordering");

        emit log(
            "BUG #2 confirmed: reordering identical criteria items flips a "
            "CONTRACT order between ADVANCED and STANDARD."
        );
    }
}
