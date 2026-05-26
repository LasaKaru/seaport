// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * Differential PoC: hand-rolled assembly EIP-712 hash vs reference Solidity
 * implementation.
 *
 * Seaport computes the order hash via hand-written assembly in
 * `_deriveOrderHash` (GettersAndDerivers / ConsiderationEncoder). If the
 * assembly diverges from the EIP-712 spec, signatures could potentially be
 * crafted to validate against parameters that differ from what the rest of
 * the protocol observes.
 *
 * This probe builds a reference hash purely from spec-compliant
 * `abi.encode` calls (which are EVM-verified) and asserts equality against
 * `consideration.getOrderHash()` across fuzzed inputs.
 *
 * If any input produces a mismatch, that's a finding.
 */

import { OrderType, ItemType } from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    OrderComponents,
    OfferItem,
    ConsiderationItem
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

contract PoCDifferentialHash is BaseOrderTest {
    // Spec-compliant typehash strings (copied verbatim from ConsiderationBase).
    bytes32 constant OFFER_ITEM_TYPEHASH =
        keccak256(
            "OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
        );

    bytes32 constant CONSIDERATION_ITEM_TYPEHASH =
        keccak256(
            "ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)"
        );

    bytes32 constant ORDER_TYPEHASH =
        keccak256(
            "OrderComponents(address offerer,address zone,OfferItem[] offer,ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,uint256 counter)ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
        );

    function _hashOfferItem(OfferItem memory item) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            OFFER_ITEM_TYPEHASH,
            item.itemType,
            item.token,
            item.identifierOrCriteria,
            item.startAmount,
            item.endAmount
        ));
    }

    function _hashConsiderationItem(ConsiderationItem memory item) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            CONSIDERATION_ITEM_TYPEHASH,
            item.itemType,
            item.token,
            item.identifierOrCriteria,
            item.startAmount,
            item.endAmount,
            item.recipient
        ));
    }

    function _referenceOrderHash(OrderComponents memory c) internal pure returns (bytes32) {
        bytes32[] memory offerHashes = new bytes32[](c.offer.length);
        for (uint256 i; i < c.offer.length; ++i) {
            offerHashes[i] = _hashOfferItem(c.offer[i]);
        }

        bytes32[] memory considHashes = new bytes32[](c.consideration.length);
        for (uint256 i; i < c.consideration.length; ++i) {
            considHashes[i] = _hashConsiderationItem(c.consideration[i]);
        }

        return keccak256(abi.encode(
            ORDER_TYPEHASH,
            c.offerer,
            c.zone,
            keccak256(abi.encodePacked(offerHashes)),
            keccak256(abi.encodePacked(considHashes)),
            c.orderType,
            c.startTime,
            c.endTime,
            c.zoneHash,
            c.salt,
            c.conduitKey,
            c.counter
        ));
    }

    // ---------- D1: simple order ----------
    function test_D1_simpleOrderHash() public {
        OfferItem[] memory offer = new OfferItem[](1);
        offer[0] = OfferItem({
            itemType: ItemType.ERC721,
            token: address(test721_1),
            identifierOrCriteria: 7,
            startAmount: 1,
            endAmount: 1
        });

        ConsiderationItem[] memory consid = new ConsiderationItem[](1);
        consid[0] = ConsiderationItem({
            itemType: ItemType.NATIVE,
            token: address(0),
            identifierOrCriteria: 0,
            startAmount: 1 ether,
            endAmount: 1 ether,
            recipient: payable(alice)
        });

        OrderComponents memory c = OrderComponents({
            offerer: alice,
            zone: address(0),
            offer: offer,
            consideration: consid,
            orderType: OrderType.FULL_OPEN,
            startTime: 1,
            endTime: 100,
            zoneHash: bytes32(0),
            salt: 0,
            conduitKey: bytes32(0),
            counter: 0
        });

        bytes32 seaport_h = consideration.getOrderHash(c);
        bytes32 ref_h = _referenceOrderHash(c);

        assertEq(seaport_h, ref_h, "FINDING D1: order hash mismatch (assembly vs spec)");
    }

    // ---------- D2: order with multiple offer + consideration items ----------
    function test_D2_multiItemOrderHash() public {
        OfferItem[] memory offer = new OfferItem[](3);
        offer[0] = OfferItem({
            itemType: ItemType.ERC1155,
            token: address(test1155_1),
            identifierOrCriteria: 42,
            startAmount: 10,
            endAmount: 10
        });
        offer[1] = OfferItem({
            itemType: ItemType.ERC20,
            token: address(token1),
            identifierOrCriteria: 0,
            startAmount: 1000,
            endAmount: 2000
        });
        offer[2] = OfferItem({
            itemType: ItemType.ERC721_WITH_CRITERIA,
            token: address(test721_1),
            identifierOrCriteria: uint256(keccak256("merkle-root")),
            startAmount: 1,
            endAmount: 1
        });

        ConsiderationItem[] memory consid = new ConsiderationItem[](2);
        consid[0] = ConsiderationItem({
            itemType: ItemType.NATIVE,
            token: address(0),
            identifierOrCriteria: 0,
            startAmount: 5 ether,
            endAmount: 1 ether,
            recipient: payable(alice)
        });
        consid[1] = ConsiderationItem({
            itemType: ItemType.ERC20,
            token: address(token2),
            identifierOrCriteria: 0,
            startAmount: 500,
            endAmount: 500,
            recipient: payable(bob)
        });

        OrderComponents memory c = OrderComponents({
            offerer: alice,
            zone: bob,
            offer: offer,
            consideration: consid,
            orderType: OrderType.FULL_RESTRICTED,
            startTime: 100,
            endTime: 200,
            zoneHash: keccak256("zone-hash"),
            salt: 0xdeadbeef,
            conduitKey: bytes32(uint256(1)),
            counter: 7
        });

        bytes32 seaport_h = consideration.getOrderHash(c);
        bytes32 ref_h = _referenceOrderHash(c);

        assertEq(seaport_h, ref_h, "FINDING D2: multi-item order hash mismatch");
    }

    // ---------- D3: empty offer / empty consideration edge cases ----------
    function test_D3_emptyArraysOrderHash() public {
        OfferItem[] memory empty1 = new OfferItem[](0);
        ConsiderationItem[] memory empty2 = new ConsiderationItem[](0);

        OrderComponents memory c = OrderComponents({
            offerer: alice,
            zone: address(0),
            offer: empty1,
            consideration: empty2,
            orderType: OrderType.FULL_OPEN,
            startTime: 0,
            endTime: type(uint256).max,
            zoneHash: bytes32(0),
            salt: 0,
            conduitKey: bytes32(0),
            counter: 0
        });

        bytes32 seaport_h = consideration.getOrderHash(c);
        bytes32 ref_h = _referenceOrderHash(c);

        assertEq(seaport_h, ref_h, "FINDING D3: empty-array order hash mismatch");
    }

    struct FuzzIn {
        address offerer;
        address zone;
        uint8 itemType1;
        address token;
        uint256 id;
        uint128 startAmt;
        uint128 endAmt;
        uint8 orderType;
        uint256 startTime;
        uint256 endTime;
        bytes32 zoneHash;
        uint256 salt;
        bytes32 conduitKey;
        uint256 counter;
    }

    // ---------- D4: fuzzed differential ----------
    function testFuzz_D4_orderHashDifferential(FuzzIn memory f) public {
        f.itemType1 = uint8(uint256(f.itemType1) % 6);
        f.orderType = uint8(uint256(f.orderType) % 5);

        OfferItem[] memory offer = new OfferItem[](1);
        offer[0] = OfferItem({
            itemType: ItemType(f.itemType1),
            token: f.token,
            identifierOrCriteria: f.id,
            startAmount: f.startAmt,
            endAmount: f.endAmt
        });

        ConsiderationItem[] memory consid = new ConsiderationItem[](1);
        consid[0] = ConsiderationItem({
            itemType: ItemType(f.itemType1),
            token: f.token,
            identifierOrCriteria: f.id,
            startAmount: f.startAmt,
            endAmount: f.endAmt,
            recipient: payable(f.offerer)
        });

        OrderComponents memory c = OrderComponents({
            offerer: f.offerer,
            zone: f.zone,
            offer: offer,
            consideration: consid,
            orderType: OrderType(f.orderType),
            startTime: f.startTime,
            endTime: f.endTime,
            zoneHash: f.zoneHash,
            salt: f.salt,
            conduitKey: f.conduitKey,
            counter: f.counter
        });

        bytes32 seaport_h = consideration.getOrderHash(c);
        bytes32 ref_h = _referenceOrderHash(c);

        assertEq(seaport_h, ref_h, "FINDING D4: fuzzed order hash mismatch");
    }

    // ---------- D5: large arrays (memory-layout sensitive) ----------
    function test_D5_largeArrayOrderHash() public {
        OfferItem[] memory offer = new OfferItem[](20);
        for (uint256 i; i < 20; ++i) {
            offer[i] = OfferItem({
                itemType: ItemType(uint8(i % 5)),
                token: address(uint160(0x1000 + i)),
                identifierOrCriteria: i * 17,
                startAmount: i + 1,
                endAmount: i + 2
            });
        }

        ConsiderationItem[] memory consid = new ConsiderationItem[](20);
        for (uint256 i; i < 20; ++i) {
            consid[i] = ConsiderationItem({
                itemType: ItemType(uint8(i % 5)),
                token: address(uint160(0x2000 + i)),
                identifierOrCriteria: i * 31,
                startAmount: i * 10 + 1,
                endAmount: i * 10 + 2,
                recipient: payable(address(uint160(0x3000 + i)))
            });
        }

        OrderComponents memory c = OrderComponents({
            offerer: alice,
            zone: bob,
            offer: offer,
            consideration: consid,
            orderType: OrderType.PARTIAL_RESTRICTED,
            startTime: 1,
            endTime: 1000,
            zoneHash: keccak256("z"),
            salt: 1234567890,
            conduitKey: bytes32(uint256(99)),
            counter: 42
        });

        bytes32 seaport_h = consideration.getOrderHash(c);
        bytes32 ref_h = _referenceOrderHash(c);

        assertEq(seaport_h, ref_h, "FINDING D5: large-array order hash mismatch");
    }
}
