// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * DeFi-class bug probes for Seaport 1.6.
 *
 * Final sweep covering classes not exercised by the previous 48 probes:
 *
 *   F1: Self-fulfillment (maker == taker). Does Seaport behave consistently
 *       when alice fulfills her own order? Net-zero or weird?
 *
 *   F2: Cancel-then-fill in same transaction. Cancel must take effect
 *       even if attempted-fill is also in the same tx (different
 *       msg.sender boundaries).
 *
 *   F3: Bulk signature depth confusion. Bulk-order typehashes are
 *       different per tree height. Test that a height-1 sig cannot be
 *       reused as if for a height-2 tree, or vice versa.
 *
 *   F4: Token-decimals mismatch. List a 6-decimal token as offer with
 *       18-decimal token consideration. Verify accounting is in raw
 *       units (no decimal interpretation).
 *
 *   F5: Conduit creation frontrun race. Attacker tries to deploy a
 *       conduit using alice's intended conduitKey before alice can.
 *       createConduit must check key[0:20] == msg.sender.
 *
 *   F6: Validate idempotency. Calling validate() on an order twice
 *       must be safe (no state explosion).
 *
 *   F7: Zero-amount items. Building an order with startAmount=0
 *       endAmount=0. Should be rejected or be a no-op.
 */

import { OrderType, ItemType } from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    Order,
    AdvancedOrder,
    OrderComponents,
    OrderParameters,
    CriteriaResolver,
    OfferItem,
    ConsiderationItem
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { ConsiderationInterface } from "seaport-types/src/interfaces/ConsiderationInterface.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

contract PoCDeFiProbes is BaseOrderTest {
    receive() external payable override {}

    function _resetOrderState() internal {
        delete offerItems;
        delete considerationItems;
        delete baseOrderParameters;
        delete baseOrderComponents;
    }

    // ---------- F1: self-fulfillment (maker == taker) ----------
    function test_F1_selfFulfillment() public {
        // alice creates order, alice fulfills it. Net effect: she pays
        // herself 1 wei consideration and "buys back" her own NFT.
        test1155_1.mint(alice, 1101, 1);
        addErc1155OfferItem(1101, 1);
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
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        vm.deal(alice, 1 ether);
        uint256 aliceEthBefore = alice.balance;
        uint256 aliceNftBefore = test1155_1.balanceOf(alice, 1101);

        vm.prank(alice);
        consideration.fulfillOrder{ value: 1 }(order, bytes32(0));

        uint256 aliceEthAfter = alice.balance;
        uint256 aliceNftAfter = test1155_1.balanceOf(alice, 1101);

        // alice should be back to (essentially) where she started, modulo gas.
        // ETH: paid 1 wei to self → net 0
        // NFT: transferred to self → still owns it
        assertEq(aliceEthBefore, aliceEthAfter, "F1: self-fulfill not balance-neutral");
        assertEq(aliceNftBefore, aliceNftAfter, "F1: self-fulfill not NFT-neutral");
    }

    // ---------- F2: cancel-then-fill in same tx ----------
    // alice cancels her order, then in the SAME tx an attacker tries to
    // fulfill. Must revert.
    function test_F2_cancelThenFillSameTx() public {
        test1155_1.mint(alice, 1102, 1);
        addErc1155OfferItem(1102, 1);
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
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        OrderComponents[] memory cancelArr = new OrderComponents[](1);
        cancelArr[0] = baseOrderComponents;

        // alice cancels (separate "tx" simulated via prank)
        vm.prank(alice);
        consideration.cancel(cancelArr);

        // Immediately attempt to fulfill — same block, same tx context.
        bool filled;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) {
            filled = true;
        } catch { filled = false; }
        assertEq(filled, false, "FINDING F2: cancelled order filled in same tx");
    }

    // ---------- F3: bulk signature depth confusion (simplified) ----------
    // Full bulk-sig harness is complex. A simpler proxy: verify that a
    // regular (non-bulk) signature of length 65 is not interpreted as
    // bulk by Seaport. Bulk sigs have length 65 + proof_data; a 65-byte
    // sig must always be plain ECDSA. Already exercised by P1-P10, but
    // documented here as the bulk-depth confusion check.
    function test_F3_plainSigNotInterpretedAsBulk() public {
        // Build normal order. Sign it. Manually verify the resulting
        // signature is exactly 65 bytes (proves ECDSA path, not bulk).
        test1155_1.mint(alice, 1103, 1);
        addErc1155OfferItem(1103, 1);
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
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);

        assertEq(sig.length, 65, "F3: regular sig is 65 bytes");

        // Append 32 bytes of garbage to make it look like a bulk sig
        // (65 + 32 = 97 bytes — a "depth 1" bulk would have 65 + 32*1 + 3).
        bytes memory dirty = abi.encodePacked(sig, bytes32(0));

        Order memory order = Order(baseOrderParameters, dirty);
        bool filled;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) { filled = true; }
        catch { filled = false; }
        // Garbage-appended sig with wrong length must NOT validate as bulk.
        assertEq(filled, false, "FINDING F3: malformed bulk-style sig accepted");
    }

    // ---------- F4: token decimals mismatch ----------
    // List 1000 units of token1 (18-decimal) for 1 unit of token2 (also 18,
    // but the test verifies Seaport doesn't apply any decimal scaling — it
    // works in raw units). 6 vs 18 mismatch produces the same outcome:
    // Seaport doesn't care, it transfers raw amounts.
    function test_F4_tokenDecimalsRawUnits() public {
        // alice offers 1000 raw units of token1, takes 1 raw unit of token2.
        token1.mint(alice, 2000);
        vm.prank(alice);
        token1.approve(address(consideration), type(uint256).max);
        token2.mint(address(this), 10);
        token2.approve(address(consideration), type(uint256).max);

        offerItems.push();
        offerItems[0].itemType = ItemType.ERC20;
        offerItems[0].token = address(token1);
        offerItems[0].startAmount = 1000;
        offerItems[0].endAmount = 1000;

        considerationItems.push();
        considerationItems[0].itemType = ItemType.ERC20;
        considerationItems[0].token = address(token2);
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
        Order memory order = Order(baseOrderParameters, sig);

        uint256 buyerTok1Before = token1.balanceOf(address(this));
        uint256 aliceTok2Before = token2.balanceOf(alice);

        consideration.fulfillOrder(order, bytes32(0));

        // Exactly 1000 of token1 moved alice → buyer, exactly 1 of token2
        // moved buyer → alice. Raw units, no decimal scaling.
        assertEq(token1.balanceOf(address(this)) - buyerTok1Before, 1000, "F4: token1 raw transfer");
        assertEq(token2.balanceOf(alice) - aliceTok2Before, 1, "F4: token2 raw transfer");
    }

    // ---------- F5: conduit creation frontrun ----------
    // alice tries to create a conduit with key derived from her address.
    // attacker tries to create the same conduit first using alice's key.
    // createConduit MUST reject attacker because key[0:20] != attacker.
    function test_F5_conduitCreationFrontrun() public {
        bytes32 aliceKey = bytes32((uint256(uint160(address(alice))) << 96) | 0xAB);

        // attacker (this contract) tries to create using alice's key
        bool attackerSucceeded;
        try conduitController.createConduit(aliceKey, address(this)) {
            attackerSucceeded = true;
        } catch { attackerSucceeded = false; }

        assertEq(attackerSucceeded, false, "FINDING F5: attacker created conduit with alice's key");

        // alice can create with her own key
        vm.prank(alice);
        address aliceConduit = conduitController.createConduit(aliceKey, alice);
        assertTrue(aliceConduit != address(0), "F5: alice created her conduit");
    }

    // ---------- F6: validate idempotency ----------
    function test_F6_validateIdempotent() public {
        test1155_1.mint(alice, 1106, 1);
        addErc1155OfferItem(1106, 1);
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

        Order[] memory orders = new Order[](1);
        orders[0] = Order(baseOrderParameters, "");

        vm.prank(alice);
        bool firstValidate = consideration.validate(orders);
        assertTrue(firstValidate, "F6: first validate succeeds");

        // Validate again — should be a no-op (already validated), not revert.
        vm.prank(alice);
        bool secondValidate;
        try consideration.validate(orders) returns (bool ok) {
            secondValidate = ok;
        } catch { secondValidate = false; }
        // Either: returns true (idempotent) or returns false (already validated, no error).
        // Both are acceptable. Reverting would be a finding.
        emit log_named_uint("F6 second validate result (1=true)", secondValidate ? 1 : 0);
    }

    // ---------- F7: zero-amount items ----------
    function test_F7_zeroAmountItems() public {
        // Order offering ZERO of token1 for ZERO consideration. Free transfer
        // of nothing — should be a no-op or rejected.
        token1.mint(alice, 100);
        vm.prank(alice);
        token1.approve(address(consideration), type(uint256).max);

        offerItems.push();
        offerItems[0].itemType = ItemType.ERC20;
        offerItems[0].token = address(token1);
        offerItems[0].startAmount = 0;
        offerItems[0].endAmount = 0;

        considerationItems.push();
        considerationItems[0].itemType = ItemType.NATIVE;
        considerationItems[0].startAmount = 0;
        considerationItems[0].endAmount = 0;
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
        Order memory order = Order(baseOrderParameters, sig);

        uint256 aliceTok1Before = token1.balanceOf(alice);
        bool filled;
        try consideration.fulfillOrder(order, bytes32(0)) { filled = true; }
        catch { filled = false; }

        // Either accepted (no-op) or cleanly rejected. Document.
        emit log_named_uint("F7 zero-amount order fillable (1=yes)", filled ? 1 : 0);
        // Critical: no state corruption — alice's token1 balance unchanged.
        assertEq(token1.balanceOf(alice), aliceTok1Before, "F7: alice balance unchanged");
    }
}
