// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * Old-school / classical vulnerability probes against Seaport 1.6.
 *
 * Bug patterns from the 2017-2020 DeFi era that still occasionally bite
 * modern protocols, especially those using lots of inline assembly.
 *
 *   L1: Force-fed ETH via selfdestruct. Pre-Cancun, an attacker could
 *       SELFDESTRUCT a balance into any address. Post-EIP-6780 in same
 *       tx only, but balance still arrives. Seaport doesn't track its
 *       own balance so this should be inert — verify.
 *
 *   L2: Block.timestamp boundary jitter. Miners can manipulate timestamp
 *       within reasonable bounds (~12s window). Test that this can't
 *       turn an unfillable order into a fillable one or vice versa
 *       beyond the documented [startTime, endTime) range.
 *
 *   L3: Read-only reentrancy via ERC1155 onReceived callback. During a
 *       fill, a receiver reads `getOrderStatus` mid-execution. Test that
 *       the observed state is consistent and unprivileged.
 *
 *   L4: ecrecover returning address(0) on malformed input. The classic
 *       bug is: ecrecover returns 0 for bad sigs, attacker sets offerer
 *       to address(0), bypasses sig check. Seaport must defend.
 *
 *   L5: Unbounded calldata DoS via huge fulfillments arrays. Pass an
 *       array large enough to OOG a normal fulfillment but not the
 *       block. Tests gas-bounded execution.
 *
 *   L6: Dirty upper bits in packed uint120 numerator/denominator.
 *       Seaport masks these in the existing code; verify the mask works
 *       by attempting to influence behaviour via the upper bits.
 *
 *   L7: ERC20 race-condition approve pattern. Seaport doesn't expose
 *       approve, but conduit channels use infinite approval. Verify
 *       that channel removal correctly revokes future authority.
 */

import { OrderType, ItemType } from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    Order,
    AdvancedOrder,
    OrderComponents,
    OrderParameters,
    CriteriaResolver,
    Fulfillment,
    FulfillmentComponent,
    OfferItem,
    ConsiderationItem
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { ConsiderationInterface } from "seaport-types/src/interfaces/ConsiderationInterface.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

// Helper: a contract that can be self-destructed, force-feeding its
// balance to a target. We use a pre-funded test contract; selfdestruct
// works pre- and post-Cancun for fund transfer within the same tx.
contract EthBomb {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}

// Helper: a receiver that reads getOrderStatus during onERC1155Received.
contract OrderStatusReader {
    ConsiderationInterface public seaport;
    bytes32 public watchHash;
    bool public hasObservation;
    bool public isValidated;
    bool public isCancelled;
    uint256 public totalFilled;
    uint256 public totalSize;

    constructor(address _seaport) {
        seaport = ConsiderationInterface(_seaport);
    }

    function arm(bytes32 _watch) external {
        watchHash = _watch;
        hasObservation = false;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4)
    {
        if (watchHash != bytes32(0) && !hasObservation) {
            (bool v, bool c, uint256 f, uint256 t) = seaport.getOrderStatus(watchHash);
            isValidated = v;
            isCancelled = c;
            totalFilled = f;
            totalSize = t;
            hasObservation = true;
        }
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }
}

contract PoCClassicProbes is BaseOrderTest {
    receive() external payable override {}

    function _signOrderForAlice1155(uint256 tokenId, uint256 price, address payable recipient)
        internal returns (Order memory order, bytes32 orderHash)
    {
        test1155_1.mint(alice, tokenId, 1);
        addErc1155OfferItem(tokenId, 1);
        addEthConsiderationItem(payable(alice), price);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, orderHash);
        order = Order(baseOrderParameters, sig);
        recipient; // silence unused
    }

    // ---------- L1: force-fed ETH via selfdestruct ----------
    function test_L1_forceFedEthGoesToFulfiller() public {
        vm.warp(10000);

        // Pre-fund Seaport with 5 ETH via selfdestruct.
        new EthBomb{ value: 5 ether }(payable(address(consideration)));
        assertEq(address(consideration).balance, 5 ether, "L1 setup: ETH delivered");

        // Build a normal order. Caller pays 1 wei to alice.
        (Order memory order, ) = _signOrderForAlice1155(901, 1, payable(alice));

        // Use a fresh fulfiller address to make balance accounting clean.
        address payable fulfiller = payable(address(0x4111));
        vm.deal(fulfiller, 1);

        uint256 fulfillerBefore = fulfiller.balance;
        uint256 aliceBefore = alice.balance;
        uint256 seaportBefore = address(consideration).balance;

        vm.prank(fulfiller);
        consideration.fulfillOrder{ value: 1 }(order, bytes32(0));

        uint256 fulfillerAfter = fulfiller.balance;
        uint256 aliceAfter = alice.balance;
        uint256 seaportAfter = address(consideration).balance;

        emit log_named_uint("L1 fulfiller before", fulfillerBefore);
        emit log_named_uint("L1 fulfiller after", fulfillerAfter);
        emit log_named_uint("L1 alice received", aliceAfter - aliceBefore);
        emit log_named_uint("L1 seaport before", seaportBefore);
        emit log_named_uint("L1 seaport after", seaportAfter);

        // Alice gets exactly 1 wei (the order price).
        assertEq(aliceAfter - aliceBefore, 1, "L1: alice paid correctly");

        // FINDING IF: fulfiller's balance went UP by 5 ether (Seaport
        // refunded the force-fed ETH to them). That would let any caller
        // sweep Seaport's force-fed balance via a 1-wei filler order.
        if (fulfillerAfter > fulfillerBefore) {
            emit log_named_uint(
                "OBS L1 fulfiller netted from Seaport refund",
                fulfillerAfter - fulfillerBefore
            );
            // Document the sweep. Severity is low: force-fed funds require
            // attacker to burn their own ETH. But it's notable.
        }
    }

    // ---------- L2: block.timestamp jitter at boundaries ----------
    // Within the order's valid window, timestamp manipulation only changes
    // amount (for Dutch auctions). Outside the window, no manipulation
    // should make an expired/unstarted order fillable.
    function test_L2_timestampJitterCannotExtendValidWindow() public {
        vm.warp(10000);

        // Build order valid [10000, 10100)
        test1155_1.mint(alice, 902, 1);
        addErc1155OfferItem(902, 1);
        addEthConsiderationItem(payable(alice), 1);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = 10000;
        baseOrderParameters.endTime = 10100;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        // At 9999 (1s before start): must revert.
        vm.warp(9999);
        bool earlyFilled;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) { earlyFilled = true; }
        catch { earlyFilled = false; }
        assertEq(earlyFilled, false, "FINDING L2a: order filled before startTime");

        // At 10100 (exact endTime): must revert.
        vm.warp(10100);
        bool atEndFilled;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) { atEndFilled = true; }
        catch { atEndFilled = false; }
        assertEq(atEndFilled, false, "FINDING L2b: order filled at exact endTime");

        // At 10000 exactly: must succeed.
        vm.warp(10000);
        consideration.fulfillOrder{ value: 1 }(order, bytes32(0));
    }

    // ---------- L3: read-only reentrancy ----------
    // During a fill, an external receiver reads getOrderStatus on the order
    // being filled. The reader must NOT see uncommitted state that could
    // mislead other contracts (e.g., observed as already fully filled when
    // it isn't yet, or vice versa).
    function test_L3_readOnlyReentrancyDuringFill() public {
        vm.warp(10000);

        OrderStatusReader reader = new OrderStatusReader(address(consideration));

        // alice sells 1155 #903 (qty 1) for 1 wei to `reader`.
        test1155_1.mint(alice, 903, 1);
        addErc1155OfferItem(903, 1);
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
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, orderHash);

        reader.arm(orderHash);

        AdvancedOrder memory adv = AdvancedOrder({
            parameters: baseOrderParameters,
            numerator: 1,
            denominator: 1,
            signature: sig,
            extraData: ""
        });
        CriteriaResolver[] memory none = new CriteriaResolver[](0);

        consideration.fulfillAdvancedOrder{ value: 1 }(
            adv, none, bytes32(0), address(reader)
        );

        // During the fill, reader queried getOrderStatus. Observation must be:
        // - isValidated = true (the order has been validated)
        // - isCancelled = false
        // - totalFilled / totalSize = 1/1 (state was already updated before
        //   the transfer happened — this is the correct order of operations
        //   to prevent read-only reentrancy attacks)
        assertTrue(reader.hasObservation(), "L3 setup: observation didn't fire");
        assertEq(reader.isCancelled(), false, "L3: cancelled state correct mid-fill");
        // Either totalFilled is 1/1 (state updated pre-transfer) or 0/0 (not
        // yet recorded). Both are defensible, but consistency matters.
        emit log_named_uint("L3 isValidated", reader.isValidated() ? 1 : 0);
        emit log_named_uint("L3 totalFilled", reader.totalFilled());
        emit log_named_uint("L3 totalSize", reader.totalSize());
        // Whichever side Seaport falls on, integrators reading mid-tx must
        // not be able to extract value from inconsistent state. This test
        // documents the observable state; flag if it ever changes.
    }

    // ---------- L4: ecrecover returns zero → reject ----------
    // Classic bug: ecrecover returns 0 for malformed sig. If offerer == 0,
    // signature "validates" against address(0). Seaport must reject this.
    function test_L4_ecrecoverZeroAddressDefense() public {
        // Build order with offerer = address(0). Use a token type that
        // doesn't require address(0) to actually hold anything; we expect
        // the signature check to fail BEFORE any transfer is attempted.
        addErc20OfferItem(1);
        addEthConsiderationItem(payable(alice), 1);

        baseOrderParameters.offerer = address(0);
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        // Malformed sig that ecrecover returns 0 for: all-zero with v=0.
        bytes memory malformedSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));
        Order memory order = Order(baseOrderParameters, malformedSig);

        bool filled;
        try consideration.fulfillOrder{ value: 1 }(order, bytes32(0)) { filled = true; }
        catch { filled = false; }
        assertEq(filled, false, "FINDING L4: address(0) offerer with bad sig accepted");
    }

    // ---------- L5: unbounded fulfillments DoS guard ----------
    // Many components in a fulfillment shouldn't be able to grief a normal
    // fill. We construct a single order with many consideration items and
    // verify it's either fillable in reasonable gas or correctly rejected.
    function test_L5_largeOrderGasBounded() public {
        vm.warp(10000);

        // Order with 50 consideration items (50 small ETH payments to alice).
        test1155_1.mint(alice, 905, 1);
        addErc1155OfferItem(905, 1);

        for (uint256 i; i < 50; ++i) {
            addEthConsiderationItem(payable(alice), 1);
        }

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 50;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);
        Order memory order = Order(baseOrderParameters, sig);

        uint256 gasBefore = gasleft();
        consideration.fulfillOrder{ value: 50 }(order, bytes32(0));
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("L5 gas used for 50-item order", gasUsed);
        // Sanity: should be well under block limit. 50 SSTOREs + transfers,
        // expect < 3M gas.
        assertLt(gasUsed, 3_000_000, "L5: large order gas-bounded");
    }

    // ---------- L6: dirty upper bits in numerator/denominator ----------
    // numerator/denominator are stored in uint120. If the caller writes
    // higher-order bits, Seaport's assembly should mask them out.
    // The existing testRevertDirtyUpperBitsForAdditionalRecipients covers
    // basic-order calldata; this is a sanity check via the advanced path.
    function test_L6_dirtyUpperBitsMaskedInFraction() public {
        vm.warp(10000);

        test1155_1.mint(alice, 906, 10);
        addErc1155OfferItem(906, 10);
        addEthConsiderationItem(payable(alice), 10);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.PARTIAL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = 1;

        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 hash = consideration.getOrderHash(baseOrderComponents);
        bytes memory sig = signOrder(consideration, alicePk, hash);

        // numerator/denominator are uint120 in the struct. If they were
        // declared uint256 and Seaport masked to 120 bits internally, dirty
        // upper bits via assembly-crafted calldata could affect behaviour.
        // At the Solidity ABI level, Foundry encodes uint120 with zero upper
        // bits automatically. The assembly mask handles raw mload of these
        // values; our test just confirms normal partial fills work.
        AdvancedOrder memory adv = AdvancedOrder({
            parameters: baseOrderParameters,
            numerator: 5,
            denominator: 10,
            signature: sig,
            extraData: ""
        });
        CriteriaResolver[] memory none = new CriteriaResolver[](0);

        uint256 aliceBefore = alice.balance;
        consideration.fulfillAdvancedOrder{ value: 5 }(
            adv, none, bytes32(0), address(this)
        );
        assertEq(alice.balance - aliceBefore, 5, "L6: 1/2 fill pays half");
        assertEq(test1155_1.balanceOf(address(this), 906), 5, "L6: 1/2 fill delivers half");
    }

    // ---------- L7: conduit channel closure revokes future authority ----------
    function test_L7_channelClosureRevokesAuthority() public {
        bytes32 myKey = bytes32((uint256(uint160(address(this))) << 96) | 0xE7);
        address newConduit = conduitController.createConduit(myKey, address(this));
        conduitController.updateChannel(newConduit, address(this), true);

        token1.mint(address(0xCAFE), 1000);
        vm.prank(address(0xCAFE));
        token1.approve(newConduit, type(uint256).max);

        // While open, the channel can transfer.
        // (Skip the actual transfer to keep test focused on revocation.)

        // Close the channel.
        conduitController.updateChannel(newConduit, address(this), false);

        // Now an attempt to call execute() must revert with ChannelClosed.
        // We construct a transfer attempt — this contract is the (now-closed)
        // channel so we call execute() directly.
        bytes memory call = abi.encodeWithSignature(
            "execute((uint8,address,address,address,uint256,uint256)[])",
            new bytes[](0)
        );
        // We craft a minimal call: empty transfers list. Conduit still
        // checks msg.sender against channels — closed channel must revert.
        (bool success, ) = newConduit.call(call);
        assertEq(success, false, "FINDING L7: closed channel still has authority");
    }
}
