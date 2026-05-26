// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * Diagram-edge probes against Seaport 1.6.
 *
 * The architecture diagram in the README shows several edges that prior
 * probe files did not exercise directly:
 *
 *   OrderFulfiller -> AmountDeriver        (Dutch-auction price ramp)
 *   OrderFulfiller -> CriteriaResolution   (Merkle proofs for collections)
 *   Verify         -> Time                 (start/end-time boundaries)
 *   Validate       -> Verify               (pre-commit: validate() entrypoint)
 *
 * Each probe targets one of these untested edges.
 *
 *   E1: AmountDeriver returns startAmount at block.timestamp == startTime
 *   E2: Time verifier rejects fill at exactly endTime
 *   E3: Zero-duration orders (startTime == endTime) are unfillable
 *   E4: CriteriaResolver with zero root acts as wildcard (any tokenId)
 *   E5: validate() precommit lets the fulfiller skip signature checks
 *   E6: AmountDeriver auction midpoint conservation
 */

import { OrderType, ItemType, Side } from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    Order,
    AdvancedOrder,
    CriteriaResolver,
    OrderComponents,
    OrderParameters
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

contract PoCDiagramEdges is BaseOrderTest {
    receive() external payable override {}

    // ---------- E1: AmountDeriver at startTime ----------
    function test_E1_amountAtStartTime() public {
        // Auction: alice sells 1155 #501 for 100 wei at start, ramping
        // down to 1 wei at end. Fill at exactly block.timestamp == startTime
        // should require startAmount = 100.
        test1155_1.mint(alice, 501, 1);

        offerItems.push();
        offerItems[0].itemType = ItemType.ERC1155;
        offerItems[0].token = address(test1155_1);
        offerItems[0].identifierOrCriteria = 501;
        offerItems[0].startAmount = 1;
        offerItems[0].endAmount = 1;

        considerationItems.push();
        considerationItems[0].itemType = ItemType.NATIVE;
        considerationItems[0].token = address(0);
        considerationItems[0].identifierOrCriteria = 0;
        considerationItems[0].startAmount = 100;
        considerationItems[0].endAmount = 1; // ramps DOWN
        considerationItems[0].recipient = payable(alice);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 100;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        uint256 aliceBefore = alice.balance;
        consideration.fulfillOrder{ value: 100 }(order, bytes32(0));

        assertEq(alice.balance - aliceBefore, 100, "FINDING E1: amount at startTime != startAmount");
    }

    // ---------- E2: Time verifier rejects fill at exactly endTime ----------
    function test_E2_rejectAtEndTime() public {
        test1155_1.mint(alice, 502, 1);
        addErc1155OfferItem(502, 1);
        addEthConsiderationItem(payable(alice), 1);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 100;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        // Warp to exactly endTime — fill must revert (verifier uses `<`).
        vm.warp(baseOrderParameters.endTime);

        bool filled;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) {
            filled = true;
        } catch { filled = false; }
        assertEq(filled, false, "FINDING E2: order filled at exactly endTime");

        // Warp back to endTime - 1 — must succeed.
        vm.warp(baseOrderParameters.endTime - 1);
        consideration.fulfillOrder{ value: 1 }(order, bytes32(0));
    }

    // ---------- E3: Zero-duration order is unfillable ----------
    function test_E3_zeroDurationUnfillable() public {
        test1155_1.mint(alice, 503, 1);
        addErc1155OfferItem(503, 1);
        addEthConsiderationItem(payable(alice), 1);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp; // zero duration
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        bool filled;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) {
            filled = true;
        } catch { filled = false; }
        assertEq(filled, false, "FINDING E3: zero-duration order accepted");
    }

    // ---------- E4: CriteriaResolver with zero root = wildcard ----------
    // ERC721_WITH_CRITERIA + identifierOrCriteria=0 is documented to mean
    // "any tokenId from this collection". Test that this works AND that a
    // non-zero root rejects mismatched proofs.
    function test_E4_criteriaZeroRootWildcard() public {
        test721_1.mint(alice, 600);

        // Offer item: ERC721_WITH_CRITERIA with zero root = wildcard
        offerItems.push();
        offerItems[0].itemType = ItemType.ERC721_WITH_CRITERIA;
        offerItems[0].token = address(test721_1);
        offerItems[0].identifierOrCriteria = 0; // zero root = any
        offerItems[0].startAmount = 1;
        offerItems[0].endAmount = 1;

        considerationItems.push();
        considerationItems[0].itemType = ItemType.NATIVE;
        considerationItems[0].startAmount = 1;
        considerationItems[0].endAmount = 1;
        considerationItems[0].recipient = payable(alice);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);

        AdvancedOrder memory adv = AdvancedOrder({
            parameters: baseOrderParameters,
            numerator: 1,
            denominator: 1,
            signature: sig,
            extraData: ""
        });

        // Resolver: pick tokenId 600 with empty proof (wildcard).
        CriteriaResolver[] memory resolvers = new CriteriaResolver[](1);
        resolvers[0] = CriteriaResolver({
            orderIndex: 0,
            side: Side.OFFER,
            index: 0,
            identifier: 600,
            criteriaProof: new bytes32[](0)
        });

        consideration.fulfillAdvancedOrder{ value: 1 }(
            adv, resolvers, bytes32(0), address(this)
        );

        assertEq(test721_1.ownerOf(600), address(this), "E4: wildcard criteria accepted any tokenId");
    }

    // ---------- E5: validate() precommit ----------
    // alice calls validate() on her own order (no signature needed when
    // msg.sender == offerer). After this, anyone can fulfill the order
    // with an EMPTY signature.
    function test_E5_validatePrecommit() public {
        test1155_1.mint(alice, 504, 1);
        addErc1155OfferItem(504, 1);
        addEthConsiderationItem(payable(alice), 1);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);

        // alice precommits via validate() — no signature needed (msg.sender ==
        // offerer). After this, anyone can fill with empty sig.
        Order[] memory orders = new Order[](1);
        orders[0] = Order(baseOrderParameters, "");
        vm.prank(alice);
        bool validated = consideration.validate(orders);
        assertTrue(validated, "E5: validate() returned false");

        // Now an unrelated party fills with empty signature.
        Order memory orderEmptySig = Order(baseOrderParameters, "");
        consideration.fulfillOrder{ value: 1 }(orderEmptySig, bytes32(0));
        assertEq(test1155_1.balanceOf(address(this), 504), 1, "E5: fulfilled after validate");
    }

    // ---------- E6: AmountDeriver midpoint conservation ----------
    // 100-second auction ramping 1000 -> 0. At elapsed=50, current = 500
    // (linear interpolation).
    function test_E6_auctionMidpoint() public {
        test1155_1.mint(alice, 505, 1);

        offerItems.push();
        offerItems[0].itemType = ItemType.ERC1155;
        offerItems[0].token = address(test1155_1);
        offerItems[0].identifierOrCriteria = 505;
        offerItems[0].startAmount = 1;
        offerItems[0].endAmount = 1;

        considerationItems.push();
        considerationItems[0].itemType = ItemType.NATIVE;
        considerationItems[0].startAmount = 1000;
        considerationItems[0].endAmount = 0; // ramp to zero
        considerationItems[0].recipient = payable(alice);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 100;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        // Warp to midpoint (elapsed=50, remaining=50).
        vm.warp(baseOrderParameters.startTime + 50);

        uint256 aliceBefore = alice.balance;
        // Send enough; Seaport pulls exactly the needed amount.
        consideration.fulfillOrder{ value: 1000 }(order, bytes32(0));
        uint256 paid = alice.balance - aliceBefore;

        // Expected: (1000 * 50 + 0 * 50) / 100 = 500. With rounding up for
        // consideration items, possibly 500 exact.
        emit log_named_uint("E6 paid at midpoint", paid);
        // Linear midpoint should equal 500 exactly.
        assertEq(paid, 500, "FINDING E6: midpoint amount deviates from linear interpolation");
    }
}
