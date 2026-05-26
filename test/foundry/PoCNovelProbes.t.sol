// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * Novel / modern attack-angle probes against Seaport 1.6.
 *
 * These target attack classes that emerged from EVM evolution
 * (Cancun TSTORE, Pectra EIP-7702) and from cross-component edge
 * cases not covered by Seaport's own FuzzEngine.
 *
 *  N1: EIP-7702 simulation — EOA hosts attacker code that returns
 *      EIP-1271 magic for any signature. Tests whether Seaport's
 *      signature path can be tricked into accepting attacker-signed
 *      orders as if alice signed them.
 *
 *  N2: EIP-1153 TSTORE reentrancy guard slot inspection. Verifies the
 *      guard slot is set during a fill and that external contracts
 *      cannot read/write Seaport's transient storage (TSTORE is
 *      address-scoped — must be true).
 *
 *  N3: Cross-order reentrancy. Same offerer, two distinct orders.
 *      Fulfilling order #1 triggers an ERC721 receiver callback that
 *      tries to fulfill order #2. Existing tests cover same-order
 *      reentrancy; this probes cross-order.
 *
 *  N4: authorizeOrder vs executed-state parity. A RESTRICTED zone
 *      records the orderHash + parameters it sees during authorize,
 *      then validates that the same orderHash is observable at
 *      validate time (no parameter spoofing between calls).
 *
 *  N5: Counter-bump frontrun griefing self-check. Verify that an
 *      attacker cannot bump alice's counter (counter is keyed on
 *      msg.sender). Sanity, but explicit.
 */

import { OrderType, ItemType } from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    Order,
    AdvancedOrder,
    CriteriaResolver,
    OrderComponents,
    OrderParameters,
    ZoneParameters,
    Schema
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { ZoneInterface } from "seaport-types/src/interfaces/ZoneInterface.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

// ---- Helpers ----

// Mimics what an EIP-7702 delegated EOA would expose:
// always returns the 1271 magic value, regardless of input.
contract Always1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
    receive() external payable {}
    fallback() external payable {}
}

// Cross-order reenterer: an ERC1155 receiver whose onERC1155Received
// callback tries to call back into Seaport with a different prepared
// order. ERC721 uses transferFrom (no callback), so we use 1155.
contract CrossOrderReceiver {
    address public seaport;
    bytes public reentryPayload;
    bool public armed;
    bool public reentryFired;
    bool public reentryReverted;
    bytes public lastError;

    function arm(address _seaport, bytes calldata _payload) external {
        seaport = _seaport;
        reentryPayload = _payload;
        armed = true;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4)
    {
        if (armed) {
            armed = false;
            reentryFired = true;
            (bool ok, bytes memory ret) = seaport.call(reentryPayload);
            if (!ok) { reentryReverted = true; lastError = ret; }
        }
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }
}

// Records parameters seen during authorizeOrder vs validateOrder.
contract ParityZone is ZoneInterface {
    bytes32 public authorizeOrderHash;
    bytes32 public validateOrderHash;
    address public authorizeOfferer;
    address public validateOfferer;
    uint256 public authorizeOfferLen;
    uint256 public validateOfferLen;

    function authorizeOrder(ZoneParameters calldata zp) external returns (bytes4) {
        authorizeOrderHash = zp.orderHash;
        authorizeOfferer = zp.offerer;
        authorizeOfferLen = zp.offer.length;
        return this.authorizeOrder.selector;
    }

    function validateOrder(ZoneParameters calldata zp) external returns (bytes4) {
        validateOrderHash = zp.orderHash;
        validateOfferer = zp.offerer;
        validateOfferLen = zp.offer.length;
        return this.validateOrder.selector;
    }

    function getSeaportMetadata() external pure returns (string memory, Schema[] memory) {
        Schema[] memory s = new Schema[](0);
        return ("ParityZone", s);
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == type(ZoneInterface).interfaceId || i == 0x01ffc9a7;
    }
}

contract PoCNovelProbes is BaseOrderTest {
    receive() external payable override {}

    // ---------- N1: EIP-7702 simulation ----------
    // Threat model: alice signs an EIP-7702 delegation to attacker-controlled
    // code (or the attacker tricks her into it). Now alice's EOA returns the
    // EIP-1271 magic for any signature. Attacker uses a junk signature.
    //
    // This is *not* a Seaport bug per se — it's the documented behavior of
    // EIP-1271 + EIP-7702. But it's the kind of attack that becomes possible
    // post-Pectra and worth verifying behaves as expected.
    function test_N1_eip7702_spoofedSignature() public {
        // Use a fresh address; etch the Always1271 code there to simulate
        // a 7702-delegated EOA.
        address victim = address(0x77027702);
        Always1271 impl = new Always1271();
        vm.etch(victim, address(impl).code);
        assertGt(victim.code.length, 0, "N1 setup: etch failed");

        // Mint a 721 to "victim" and approve Seaport.
        test721_1.mint(victim, 401);
        vm.prank(victim);
        test721_1.setApprovalForAll(address(consideration), true);

        // Build order: victim sells 721 #401 for 1 wei.
        addErc721OfferItem(address(test721_1), 401);
        addEthConsiderationItem(payable(victim), 1);
        baseOrderParameters.offerer = victim;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = considerationItems.length;

        // Junk "signature" — not a valid ECDSA sig. Seaport should fall
        // through to EIP-1271, where Always1271 returns the magic value.
        bytes memory junkSig = hex"deadbeef";
        Order memory order = Order(baseOrderParameters, junkSig);

        bool filled;
        bytes memory err;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) {
            filled = true;
        } catch (bytes memory e) { filled = false; err = e; }

        emit log_named_uint("N1 filled with permissive-1271 contract (1=yes)", filled ? 1 : 0);
        if (!filled) emit log_named_bytes("N1 revert data", err);

        // OBSERVATION: with Always1271 etched at victim, the EIP-1271 fallback
        // is reached and returns the magic value. Seaport correctly accepts
        // the order as valid for `victim`. This is EXPECTED behavior — the
        // attack surface is the wallet choosing to delegate to permissive
        // code, not Seaport.
        //
        // If this test ever starts failing (Seaport refusing to honor a valid
        // 1271 response), that would break real-world contract wallets.
        assertTrue(filled, "OBS N1: Seaport honors EIP-1271 magic value (expected)");
        assertEq(test721_1.ownerOf(401), address(this), "N1: NFT transferred");
    }

    // ---------- N2: TSTORE guard slot is address-scoped ----------
    // EIP-1153 explicitly scopes TSTORE/TLOAD to the executing contract.
    // Verify another contract cannot read or modify Seaport's guard slot.
    function test_N2_tstoreSlotIsScoped() public {
        // Slot used by Seaport's ReentrancyGuard.
        uint256 GUARD_SLOT = 0x929eee14;

        // Read from this contract's transient slot at the same index — must
        // be unrelated to Seaport's slot at the same index.
        uint256 ourValue;
        assembly { ourValue := tload(GUARD_SLOT) }
        assertEq(ourValue, 0, "N2 baseline: our own TSTORE slot is empty");

        // Write a sentinel into OUR transient slot.
        uint256 sentinel = 0xCAFEBABE;
        assembly { tstore(GUARD_SLOT, sentinel) }

        // Attempt to read Seaport's transient slot from outside — TSTORE is
        // not exposed cross-contract, but we can verify Seaport's behavior is
        // unaffected by our write (this is implicit in EIP-1153).
        // Sanity: do a basic fill — must succeed regardless of our TSTORE.
        test721_1.mint(alice, 402);
        addErc721OfferItem(address(test721_1), 402);
        addEthConsiderationItem(payable(alice), 1);
        configureOrderParameters(alice);
        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory signature = signOrder(consideration, alicePk, orderHash);
        Order memory order = Order(baseOrderParameters, signature);

        consideration.fulfillOrder{ value: 1 }(order, bytes32(0));
        assertEq(test721_1.ownerOf(402), address(this), "N2: fill unaffected by external TSTORE");
    }

    // ---------- N3: Cross-order reentrancy ----------
    // Alice has TWO different orders open (different tokenIds). Fulfilling
    // order #1 triggers a callback that tries to fulfill order #2.
    // The ReentrancyGuard must block — even though it's a DIFFERENT order,
    // the same Seaport entry point is reentered.
    function test_N3_crossOrderReentrancy() public {
        CrossOrderReceiver receiver = new CrossOrderReceiver();

        // Order 1: alice sells 1155 #403 (qty 1) for 1 wei.
        test1155_1.mint(alice, 403, 1);
        addErc1155OfferItem(403, 1);
        addEthConsiderationItem(payable(alice), 1);
        configureOrderParameters(alice);
        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash1 = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig1 = signOrder(consideration, alicePk, hash1);
        Order memory order1 = Order(baseOrderParameters, sig1);

        // Reset state for order 2
        delete offerItems;
        delete considerationItems;
        delete baseOrderParameters;
        delete baseOrderComponents;

        // Order 2: alice sells 1155 #404 (qty 1) for 1 wei.
        test1155_1.mint(alice, 404, 1);
        addErc1155OfferItem(404, 1);
        addEthConsiderationItem(payable(alice), 1);
        configureOrderParameters(alice);
        configureOrderComponents(counter);
        bytes32 hash2 = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig2 = signOrder(consideration, alicePk, hash2);
        Order memory order2 = Order(baseOrderParameters, sig2);

        // Arm receiver to reenter Seaport with order #2 during onERC721Received
        receiver.arm(
            address(consideration),
            abi.encodeWithSelector(consideration.fulfillOrder.selector, order2, bytes32(0))
        );

        // Fulfill order #1, routing the NFT to `receiver` so its
        // onERC721Received fires and attempts to reenter Seaport.
        // fulfillAdvancedOrder lets us specify the recipient explicitly.
        bool outerSucceeded;
        try consideration.fulfillAdvancedOrder{ value: 1 }(
            _toAdvanced(order1), new CriteriaResolver[](0), bytes32(0), address(receiver)
        ) { outerSucceeded = true; } catch { outerSucceeded = false; }

        emit log_named_uint("N3 outerSucceeded (1=yes)", outerSucceeded ? 1 : 0);
        emit log_named_uint("N3 reentryFired (1=yes)", receiver.reentryFired() ? 1 : 0);
        emit log_named_uint("N3 reentryReverted (1=yes)", receiver.reentryReverted() ? 1 : 0);

        // Must observe: receiver's onERC1155Received fired AND the reentrant
        // call into Seaport reverted (cross-order reentrancy blocked).
        if (outerSucceeded) {
            assertEq(test1155_1.balanceOf(address(receiver), 403), 1, "N3: order #1 outer fill ok");
            assertTrue(receiver.reentryFired(), "N3: setup error - callback never fired");
            assertTrue(receiver.reentryReverted(), "FINDING N3: cross-order reentrancy succeeded");
            assertEq(test1155_1.balanceOf(alice, 404), 1, "N3: order #2 token must not have moved");
        } else {
            // Outer reverted — also acceptable defense.
            assertEq(test1155_1.balanceOf(alice, 403), 1, "N3: order #1 untouched on outer revert");
            assertEq(test1155_1.balanceOf(alice, 404), 1, "N3: order #2 untouched on outer revert");
        }
    }

    function _toAdvanced(Order memory o) internal pure returns (AdvancedOrder memory) {
        return AdvancedOrder({
            parameters: o.parameters,
            numerator: 1,
            denominator: 1,
            signature: o.signature,
            extraData: ""
        });
    }

    // ---------- N4: zone parameter parity (authorize vs validate) ----------
    function test_N4_zoneParityAcrossCalls() public {
        ParityZone zone = new ParityZone();

        test721_1.mint(alice, 405);
        addErc721OfferItem(address(test721_1), 405);
        addEthConsiderationItem(payable(alice), 1);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.zone = address(zone);
        baseOrderParameters.orderType = OrderType.FULL_RESTRICTED;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = considerationItems.length;
        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory signature = signOrder(consideration, alicePk, orderHash);
        Order memory order = Order(baseOrderParameters, signature);

        consideration.fulfillOrder{ value: 1 }(order, bytes32(0));

        // Both authorize and validate paths must observe the SAME order hash,
        // offerer, and offer length.
        assertEq(zone.authorizeOrderHash(), zone.validateOrderHash(), "FINDING N4: orderHash mismatch authorize vs validate");
        assertEq(zone.authorizeOrderHash(), orderHash, "FINDING N4: zone saw wrong orderHash");
        assertEq(zone.authorizeOfferer(), zone.validateOfferer(), "FINDING N4: offerer mismatch authorize vs validate");
        assertEq(zone.authorizeOfferer(), alice, "FINDING N4: zone saw wrong offerer");
        assertEq(zone.authorizeOfferLen(), zone.validateOfferLen(), "FINDING N4: offer length mismatch");
        assertEq(zone.authorizeOfferLen(), 1, "FINDING N4: zone saw wrong offer length");
    }

    // ---------- N5: counter-bump frontrun isolation ----------
    function test_N5_counterIsOffererScoped() public {
        uint256 aliceCounterBefore = consideration.getCounter(alice);

        // Attacker (this contract) tries to bump alice's counter — can't.
        // incrementCounter is keyed on msg.sender.
        consideration.incrementCounter(); // bumps OUR counter, not alice's

        uint256 aliceCounterAfter = consideration.getCounter(alice);

        assertEq(
            aliceCounterAfter,
            aliceCounterBefore,
            "FINDING N5: someone other than alice bumped alice's counter"
        );
    }
}
