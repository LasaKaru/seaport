// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * PoC Security Probes against Seaport 1.6 (in-scope of bounty).
 *
 * Each test attempts an attacker-favourable outcome. A FAILING probe (one that
 * succeeds at exploiting) is a finding. A PASSING probe means Seaport correctly
 * rejected the attack.
 *
 * Targeted attack classes:
 *  - P1: signature replay after order fully filled
 *  - P2: signature replay after offerer increments counter
 *  - P3: signature replay after order cancellation
 *  - P4: cross-chain replay (signature crafted for different chainid)
 *  - P5: ETH over-payment refund (refund must go to caller)
 *  - P6: signature malleability (s in upper-half should be rejected)
 *  - P7: partial-fill numerator>denominator rejection
 *  - P8: partial-fill conservation across multiple fills
 */

import {
    OrderType,
    ItemType
} from "seaport-types/src/lib/ConsiderationEnums.sol";

import {
    ConsiderationInterface
} from "seaport-types/src/interfaces/ConsiderationInterface.sol";

import {
    AdvancedOrder,
    Order,
    OrderComponents,
    OrderParameters,
    CriteriaResolver
} from "seaport-types/src/lib/ConsiderationStructs.sol";

import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

contract PoCSecurityProbes is BaseOrderTest {
    receive() external payable override {}

    // Build an order where `alice` sells ERC721 token #tokenId for `price` ETH.
    // Returns (signed Order, orderHash, components).
    function _aliceSells721ForEth(uint256 tokenId, uint256 price)
        internal
        returns (Order memory order, bytes32 orderHash, OrderComponents memory components)
    {
        test721_1.mint(alice, tokenId);
        addErc721OfferItem(address(test721_1), tokenId);
        addEthConsiderationItem(payable(alice), price);

        configureOrderParameters(alice);
        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);

        components = baseOrderComponents;
        orderHash = consideration.getOrderHash(components);

        bytes memory signature = signOrder(consideration, alicePk, orderHash);
        order = Order(baseOrderParameters, signature);
    }

    function _reset() internal {
        delete offerItems;
        delete considerationItems;
        delete baseOrderParameters;
        delete baseOrderComponents;
    }

    // ---------- P1: replay after full fulfillment ----------
    function test_P1_replayAfterFill() public {
        (Order memory order, , ) = _aliceSells721ForEth(101, 1 ether);

        // First fill — must succeed
        consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0));
        assertEq(test721_1.ownerOf(101), address(this), "P1: first fill failed");

        // Second fill — must revert
        bool secondFillSucceeded;
        try consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0)) {
            secondFillSucceeded = true;
        } catch {
            secondFillSucceeded = false;
        }
        assertEq(secondFillSucceeded, false, "FINDING P1: order filled twice");
    }

    // ---------- P2: replay after offerer increments counter ----------
    function test_P2_replayAfterCounterBump() public {
        (Order memory order, , ) = _aliceSells721ForEth(102, 1 ether);

        // Alice increments her counter, invalidating all signed orders
        vm.prank(alice);
        consideration.incrementCounter();

        bool filled;
        try consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0)) {
            filled = true;
        } catch {
            filled = false;
        }
        assertEq(filled, false, "FINDING P2: stale order filled after counter bump");
    }

    // ---------- P3: replay after cancel ----------
    function test_P3_replayAfterCancel() public {
        (Order memory order, , OrderComponents memory components) =
            _aliceSells721ForEth(103, 1 ether);

        OrderComponents[] memory comps = new OrderComponents[](1);
        comps[0] = components;

        vm.prank(alice);
        consideration.cancel(comps);

        bool filled;
        try consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0)) {
            filled = true;
        } catch {
            filled = false;
        }
        assertEq(filled, false, "FINDING P3: cancelled order was filled");
    }

    // ---------- P4: cross-chain replay ----------
    function test_P4_crossChainReplay() public {
        (Order memory order, , ) = _aliceSells721ForEth(104, 1 ether);

        // Move to a different chain — Seaport must re-derive domain separator
        // and the cached signature must no longer validate.
        vm.chainId(99999);

        bool filled;
        try consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0)) {
            filled = true;
        } catch {
            filled = false;
        }
        assertEq(filled, false, "FINDING P4: signature replayed on different chain");
    }

    // ---------- P5: ETH over-payment refund ----------
    function test_P5_overpaymentRefund() public {
        (Order memory order, , ) = _aliceSells721ForEth(105, 1 ether);

        uint256 priceRequired = 1 ether;
        uint256 paid = 5 ether;

        uint256 callerBefore = address(this).balance;
        uint256 aliceBefore = alice.balance;

        consideration.fulfillOrder{ value: paid }(order, bytes32(0));

        uint256 callerAfter = address(this).balance;
        uint256 aliceAfter = alice.balance;

        // Alice should receive exactly priceRequired.
        assertEq(aliceAfter - aliceBefore, priceRequired, "FINDING P5: alice received wrong ETH amount");

        // Caller should be debited exactly priceRequired (refund the rest).
        assertEq(callerBefore - callerAfter, priceRequired, "FINDING P5: ETH over-payment not refunded to caller");
    }

    // ---------- P6: signature malleability (high-s) ----------
    // OBSERVATION (not exploitable): Seaport's SignatureVerification calls
    // ecrecover without enforcing s in the lower-half of the curve order N.
    // Both the canonical low-s sig and a high-s + flipped-v counterpart
    // recover to the same signer and are accepted. However, order state is
    // keyed on orderHash (not signature bytes), so this does NOT enable
    // double-fill, fund theft, or state corruption.
    //
    // This test ASSERTS the observed behaviour (high-s accepted). It is
    // INFORMATIONAL ONLY and deviates from EIP-2 / OZ ECDSA hygiene.
    function test_P6_signatureMalleabilityIsAccepted_butNotExploitable() public {
        // Build a normal order.
        test721_1.mint(alice, 106);
        addErc721OfferItem(address(test721_1), 106);
        addEthConsiderationItem(payable(alice), 1 ether);
        configureOrderParameters(alice);
        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);

        // Get canonical (low-s) signature components.
        (bytes32 r, bytes32 s, uint8 v) =
            getSignatureComponents(consideration, alicePk, orderHash);

        // Flip s to upper-half by computing N - s, and flip v parity.
        bytes32 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS;
        unchecked {
            highS = bytes32(uint256(N) - uint256(s));
        }
        uint8 flippedV = v == 27 ? 28 : 27;

        bytes memory malleableSig = abi.encodePacked(r, highS, flippedV);
        Order memory order = Order(baseOrderParameters, malleableSig);

        // The malleated signature IS accepted (informational).
        consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0));
        assertEq(test721_1.ownerOf(106), address(this), "P6: order filled with malleable sig");

        // Critical: second fill with EITHER sig must revert — confirming the
        // malleability does NOT escalate to a double-fill exploit.
        bytes memory canonicalSig = abi.encodePacked(r, s, v);
        Order memory orderCanon = Order(baseOrderParameters, canonicalSig);
        bool secondFill;
        try consideration.fulfillOrder{ value: 1 ether }(orderCanon, bytes32(0)) {
            secondFill = true;
        } catch { secondFill = false; }
        assertEq(secondFill, false, "FINDING P6-CRITICAL: double-fill via signature malleability");
    }

    // ---------- P7: partial fill with numerator > denominator must revert ----------
    function test_P7_invalidFractionRejected() public {
        // Build a PARTIAL_OPEN order selling 10x ERC1155 for 10 ETH.
        test1155_1.mint(alice, 107, 10);
        addErc1155OfferItem(107, 10);
        addEthConsiderationItem(payable(alice), 10);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.PARTIAL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = considerationItems.length;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory signature = signOrder(consideration, alicePk, orderHash);

        // Construct an AdvancedOrder with numerator > denominator.
        AdvancedOrder memory adv = AdvancedOrder({
            parameters: baseOrderParameters,
            numerator: 3,
            denominator: 2, // invalid: 3/2 > 1
            signature: signature,
            extraData: ""
        });

        CriteriaResolver[] memory none = new CriteriaResolver[](0);
        bool filled;
        try consideration.fulfillAdvancedOrder{ value: 10 }(
            adv, none, bytes32(0), address(this)
        ) {
            filled = true;
        } catch {
            filled = false;
        }
        assertEq(filled, false, "FINDING P7: invalid fraction (numerator>denominator) accepted");
    }

    // ---------- P8: partial-fill conservation ----------
    // Fill 1/3 three times; alice must receive exactly 9 wei (full order value),
    // not 10 (full) and not 8 (under), under integer rounding.
    function test_P8_partialFillConservation() public {
        // Order: 9x ERC1155 #108 for 9 wei
        test1155_1.mint(alice, 108, 9);
        addErc1155OfferItem(108, 9);
        addEthConsiderationItem(payable(alice), 9);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.PARTIAL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = considerationItems.length;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory signature = signOrder(consideration, alicePk, orderHash);

        uint256 aliceBefore = alice.balance;

        CriteriaResolver[] memory none = new CriteriaResolver[](0);
        // Three 1/3 fills
        for (uint256 i = 0; i < 3; i++) {
            AdvancedOrder memory adv = AdvancedOrder({
                parameters: baseOrderParameters,
                numerator: 1,
                denominator: 3,
                signature: signature,
                extraData: ""
            });
            consideration.fulfillAdvancedOrder{ value: 3 }(
                adv, none, bytes32(0), address(this)
            );
        }

        uint256 aliceAfter = alice.balance;
        // Conservation: alice must receive exactly 9 wei (full order).
        assertEq(aliceAfter - aliceBefore, 9, "FINDING P8: partial-fill accounting drift");
        // Buyer holds full 9 of the ERC1155.
        assertEq(
            test1155_1.balanceOf(address(this), 108),
            9,
            "FINDING P8: 1155 amount mismatch after partial fills"
        );
    }
}
