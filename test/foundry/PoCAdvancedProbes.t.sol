// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * Advanced PoC probes against Seaport 1.6.
 *
 *  A1: Reentrancy via consideration ETH recipient
 *      - Order pays ETH to a contract whose receive() reenters Seaport.
 *      - Expectation: Seaport's ReentrancyGuard reverts the inner call.
 *
 *  A2: Returndata-bomb via malicious RESTRICTED zone
 *      - Order has zone = bomb contract. Zone's validateOrder returns
 *        gigabytes of returndata.
 *      - Expectation: Seaport bounds the returndata copy and either
 *        succeeds (if it only reads the 4-byte magic from scratch) or
 *        reverts cleanly without OOG-grief of the caller.
 *
 *  A3: FulfillmentComponent index out-of-range
 *      - matchAdvancedOrders with a FulfillmentComponent referencing a
 *        non-existent (orderIndex, itemIndex).
 *      - Expectation: revert with a bounds error.
 *
 *  A4: Contract offerer reentrancy during generateOrder
 *      - Contract offerer's generateOrder tries to reenter Seaport.
 *      - Expectation: reentrancy guard reverts the inner call.
 */

import { OrderType, ItemType, Side } from "seaport-types/src/lib/ConsiderationEnums.sol";
import { ConsiderationInterface } from "seaport-types/src/interfaces/ConsiderationInterface.sol";
import {
    AdvancedOrder,
    Order,
    OrderComponents,
    OrderParameters,
    CriteriaResolver,
    Fulfillment,
    FulfillmentComponent,
    OfferItem,
    ConsiderationItem,
    ZoneParameters,
    Schema,
    SpentItem,
    ReceivedItem
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { ZoneInterface } from "seaport-types/src/interfaces/ZoneInterface.sol";
import { ContractOffererInterface } from "seaport-types/src/interfaces/ContractOffererInterface.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

// ---- Malicious helpers ----

contract EthReenterer {
    address public seaport;
    bytes public payload;
    bool public armed;
    bool public reverted;
    bytes public lastError;

    function arm(address _seaport, bytes calldata _payload) external {
        seaport = _seaport;
        payload = _payload;
        armed = true;
    }

    receive() external payable {
        if (armed) {
            armed = false;
            (bool ok, bytes memory ret) = seaport.call(payload);
            if (!ok) {
                reverted = true;
                lastError = ret;
            }
        }
    }
}

contract BombZone is ZoneInterface {
    uint256 public bombSize;

    function setBombSize(uint256 s) external { bombSize = s; }

    function authorizeOrder(ZoneParameters calldata) external view returns (bytes4) {
        if (bombSize > 0) _bomb();
        return this.authorizeOrder.selector;
    }

    function validateOrder(ZoneParameters calldata) external view returns (bytes4) {
        if (bombSize > 0) _bomb();
        return this.validateOrder.selector;
    }

    function _bomb() internal view {
        uint256 size = bombSize;
        assembly {
            // Write zeros to memory then return that much.
            let m := mload(0x40)
            // Need to ensure first 32 bytes match the magic value selector
            // for a clean return path; here we abuse `return` not `revert` so
            // the call appears successful and Seaport must copy returndata.
            mstore(m, 0x0e1d31dc00000000000000000000000000000000000000000000000000000000)
            return(m, size)
        }
    }

    function getSeaportMetadata() external pure returns (string memory, Schema[] memory) {
        Schema[] memory s = new Schema[](0);
        return ("BombZone", s);
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == type(ZoneInterface).interfaceId || i == 0x01ffc9a7;
    }
}

contract ReentrantOfferer is ContractOffererInterface {
    address public seaport;
    bytes public payload;
    bool public armed;
    bool public reverted;
    bytes public lastError;

    function arm(address _seaport, bytes calldata _payload) external {
        seaport = _seaport;
        payload = _payload;
        armed = true;
    }

    function generateOrder(
        address,
        SpentItem[] calldata minimumReceived,
        SpentItem[] calldata maximumSpent,
        bytes calldata
    ) external override returns (SpentItem[] memory, ReceivedItem[] memory) {
        if (armed) {
            armed = false;
            (bool ok, bytes memory ret) = seaport.call(payload);
            if (!ok) { reverted = true; lastError = ret; }
        }
        SpentItem[] memory offer = new SpentItem[](minimumReceived.length);
        for (uint256 i; i < minimumReceived.length; ++i) offer[i] = minimumReceived[i];
        ReceivedItem[] memory consid = new ReceivedItem[](maximumSpent.length);
        for (uint256 i; i < maximumSpent.length; ++i) {
            consid[i] = ReceivedItem({
                itemType: maximumSpent[i].itemType,
                token: maximumSpent[i].token,
                identifier: maximumSpent[i].identifier,
                amount: maximumSpent[i].amount,
                recipient: payable(address(this))
            });
        }
        return (offer, consid);
    }

    function ratifyOrder(
        SpentItem[] calldata,
        ReceivedItem[] calldata,
        bytes calldata,
        bytes32[] calldata,
        uint256
    ) external pure override returns (bytes4) {
        return this.ratifyOrder.selector;
    }

    function previewOrder(
        address,
        address,
        SpentItem[] calldata,
        SpentItem[] calldata,
        bytes calldata
    ) external pure override returns (SpentItem[] memory, ReceivedItem[] memory) {
        SpentItem[] memory a; ReceivedItem[] memory b;
        return (a, b);
    }

    function getSeaportMetadata() external pure override returns (string memory, Schema[] memory) {
        Schema[] memory s = new Schema[](0);
        return ("ReentrantOfferer", s);
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == type(ContractOffererInterface).interfaceId || i == 0x01ffc9a7;
    }

    receive() external payable {}
}

contract PoCAdvancedProbes is BaseOrderTest {
    receive() external payable override {}

    // ---------- A1: ETH consideration recipient reentrancy ----------
    function test_A1_ethRecipientReentrancy() public {
        EthReenterer reenterer = new EthReenterer();
        uint256 tokenId = 201;

        // Build order: alice sells 721 #201 for 1 ETH paid to `reenterer`.
        test721_1.mint(alice, tokenId);
        addErc721OfferItem(address(test721_1), tokenId);
        addEthConsiderationItem(payable(address(reenterer)), 1 ether);
        configureOrderParameters(alice);
        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory signature = signOrder(consideration, alicePk, orderHash);
        Order memory order = Order(baseOrderParameters, signature);

        // Arm reenterer to attempt fulfilling the SAME order again on callback.
        reenterer.arm(
            address(consideration),
            abi.encodeWithSelector(consideration.fulfillOrder.selector, order, bytes32(0))
        );

        consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0));

        // Outer fill succeeded; inner reentrant call must have reverted.
        assertTrue(reenterer.reverted(), "FINDING A1: reentrant fulfillOrder succeeded");
        assertEq(test721_1.ownerOf(tokenId), address(this), "A1: outer fill ok");
    }

    // ---------- A2: Returndata-bomb zone ----------
    function test_A2_returnDataBomb() public {
        BombZone zone = new BombZone();
        uint256 tokenId = 202;

        test721_1.mint(alice, tokenId);
        addErc721OfferItem(address(test721_1), tokenId);
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

        // Set a huge bomb size — 100k bytes
        zone.setBombSize(100_000);

        // Try to fill; either Seaport bounds the returndata (succeeds or
        // reverts cleanly) OR it OOGs catastrophically.
        bool succeeded;
        uint256 gasBefore = gasleft();
        try consideration.fulfillOrder{ value: 1, gas: 30_000_000 }(order, bytes32(0)) {
            succeeded = true;
        } catch {
            succeeded = false;
        }
        uint256 gasUsed = gasBefore - gasleft();

        // A successful fill with a non-magic-returning bomb zone would be a
        // finding (zone bypass). But the bomb returns the magic value selector
        // in the first word, so it could legitimately be accepted IF Seaport
        // only reads the first 4 bytes. If Seaport copies the whole 100KB and
        // burns excessive gas, that's a griefing concern.
        emit log_named_uint("A2 gas burned", gasUsed);
        emit log_named_uint("A2 succeeded (1=yes)", succeeded ? 1 : 0);

        // Hard assertion: gas used should be bounded — < 5M gas regardless.
        assertTrue(gasUsed < 5_000_000, "FINDING A2: returndata bomb caused excessive gas burn (griefing)");
    }

    // ---------- A3: FulfillmentComponent out-of-range ----------
    function test_A3_fulfillmentComponentOOR() public {
        // Two trivial orders + a fulfillment referencing an order index
        // outside the supplied orders array. Must revert.
        test721_1.mint(alice, 203);
        addErc721OfferItem(address(test721_1), 203);
        addErc20ConsiderationItem(alice, 1);

        baseOrderParameters.offerer = alice;
        baseOrderParameters.orderType = OrderType.FULL_OPEN;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = considerationItems.length;
        uint256 counter = consideration.getCounter(alice);
        configureOrderComponents(counter);
        bytes32 orderHash = consideration.getOrderHash(baseOrderComponents);
        bytes memory signature = signOrder(consideration, alicePk, orderHash);

        AdvancedOrder[] memory orders = new AdvancedOrder[](1);
        orders[0] = AdvancedOrder({
            parameters: baseOrderParameters,
            numerator: 1,
            denominator: 1,
            signature: signature,
            extraData: ""
        });

        // Build a malformed Fulfillment: offer side points to orderIndex=5 (does not exist)
        FulfillmentComponent[] memory offerComps = new FulfillmentComponent[](1);
        offerComps[0] = FulfillmentComponent({ orderIndex: 5, itemIndex: 0 });
        FulfillmentComponent[] memory considComps = new FulfillmentComponent[](1);
        considComps[0] = FulfillmentComponent({ orderIndex: 0, itemIndex: 0 });

        Fulfillment[] memory fulfillments = new Fulfillment[](1);
        fulfillments[0] = Fulfillment({
            offerComponents: offerComps,
            considerationComponents: considComps
        });

        CriteriaResolver[] memory none = new CriteriaResolver[](0);
        bool succeeded;
        try consideration.matchAdvancedOrders(
            orders, none, fulfillments, address(this)
        ) {
            succeeded = true;
        } catch { succeeded = false; }

        assertEq(succeeded, false, "FINDING A3: out-of-range FulfillmentComponent accepted");
    }

    // ---------- A4: Contract offerer reentrancy via generateOrder ----------
    function test_A4_contractOffererReentrancy() public {
        ReentrantOfferer mal = new ReentrantOfferer();

        // Order using contract offerer (orderType = CONTRACT, offerer = mal).
        // Offer 1 wei ERC20, consider 1 wei ERC20 paid by fulfiller.
        token1.mint(address(mal), 1);
        vm.prank(address(mal));
        token1.approve(address(consideration), type(uint256).max);

        addErc20OfferItem(1);
        addErc20ConsiderationItem(payable(alice), 1);

        baseOrderParameters.offerer = address(mal);
        baseOrderParameters.orderType = OrderType.CONTRACT;
        baseOrderParameters.startTime = block.timestamp;
        baseOrderParameters.endTime = block.timestamp + 1000;
        baseOrderParameters.offer = offerItems;
        baseOrderParameters.consideration = considerationItems;
        baseOrderParameters.totalOriginalConsiderationItems = considerationItems.length;

        AdvancedOrder memory adv = AdvancedOrder({
            parameters: baseOrderParameters,
            numerator: 1,
            denominator: 1,
            signature: "",     // contract orders don't need signatures
            extraData: ""
        });

        // Arm offerer to reenter Seaport with a counter increment for itself.
        mal.arm(
            address(consideration),
            abi.encodeWithSelector(consideration.incrementCounter.selector)
        );

        CriteriaResolver[] memory none = new CriteriaResolver[](0);

        bool succeeded;
        try consideration.fulfillAdvancedOrder(
            adv, none, bytes32(0), address(this)
        ) { succeeded = true; } catch { succeeded = false; }

        // Either: outer call reverts (reentrancy detected before completion),
        // or it succeeds but mal.reverted() is true (inner reverted).
        if (succeeded) {
            assertTrue(mal.reverted(), "FINDING A4: contract offerer reentered Seaport successfully");
        } else {
            // Outer reverted — also acceptable defense.
            assertTrue(true);
        }
    }
}
