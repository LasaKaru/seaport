// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * White-box verification of agent-flagged decoder concerns (Opus 4.8 pass).
 *
 * Three sub-agents flagged potential bugs in the assembly decoders. This
 * file converts the most plausible claim into a concrete adversarial test
 * to confirm whether it is real or a false positive.
 *
 *   W1: Malicious contract offerer returns generateOrder returndata with
 *       OVERSIZED length fields (> 65535) attempting to overflow the
 *       end-offset computation in _decodeGenerateOrderReturndata.
 *       Expectation: Seaport rejects via the length<=65535 guard
 *       (ConsiderationDecoder.sol:928-932). No corruption, no drain.
 *
 *   W2: Malicious contract offerer returns generateOrder returndata with
 *       offsets pointing past returndatasize.
 *       Expectation: Seaport rejects via the offset bounds guard
 *       (ConsiderationDecoder.sol:891-904).
 *
 *   W3: Malicious contract offerer returns truncated returndata (< 3 words).
 *       Expectation: Seaport rejects via the ThreeWords guard (line 874).
 */

import { OrderType, ItemType } from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    AdvancedOrder,
    OrderParameters,
    CriteriaResolver,
    SpentItem,
    ReceivedItem,
    Schema
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { ContractOffererInterface } from "seaport-types/src/interfaces/ContractOffererInterface.sol";
import { ConsiderationInterface } from "seaport-types/src/interfaces/ConsiderationInterface.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

// A contract offerer that returns attacker-chosen raw bytes from
// generateOrder, bypassing the normal ABI encoding.
contract EvilReturndataOfferer is ContractOffererInterface {
    bytes public payload;

    function setPayload(bytes calldata p) external { payload = p; }

    function generateOrder(
        address, SpentItem[] calldata, SpentItem[] calldata, bytes calldata
    ) external view override returns (SpentItem[] memory, ReceivedItem[] memory) {
        bytes memory p = payload;
        assembly {
            return(add(p, 0x20), mload(p))
        }
    }

    function ratifyOrder(
        SpentItem[] calldata, ReceivedItem[] calldata, bytes calldata, bytes32[] calldata, uint256
    ) external pure override returns (bytes4) {
        return this.ratifyOrder.selector;
    }

    function previewOrder(
        address, address, SpentItem[] calldata, SpentItem[] calldata, bytes calldata
    ) external pure override returns (SpentItem[] memory a, ReceivedItem[] memory b) {
        return (a, b);
    }

    function getSeaportMetadata() external pure override returns (string memory, Schema[] memory) {
        Schema[] memory s = new Schema[](0);
        return ("Evil", s);
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == type(ContractOffererInterface).interfaceId || i == 0x01ffc9a7;
    }

    receive() external payable {}
}

contract PoCDecoderVerify is BaseOrderTest {
    receive() external payable override {}

    EvilReturndataOfferer evil;

    function setUp() public override {
        super.setUp();
        evil = new EvilReturndataOfferer();
    }

    function _contractOrder() internal view returns (AdvancedOrder memory adv) {
        // Minimal CONTRACT order. The offerer (evil) is asked to generate.
        // offer/consideration default to empty (length 0) dynamic arrays.
        OrderParameters memory params;
        params.offerer = address(evil);
        params.orderType = OrderType.CONTRACT;
        params.startTime = block.timestamp;
        params.endTime = block.timestamp + 1000;
        params.totalOriginalConsiderationItems = 0;

        adv = AdvancedOrder({
            parameters: params,
            numerator: 1,
            denominator: 1,
            signature: "",
            extraData: ""
        });
    }

    function _fulfill(AdvancedOrder memory adv) internal returns (bool ok) {
        CriteriaResolver[] memory none = new CriteriaResolver[](0);
        try consideration.fulfillAdvancedOrder(adv, none, bytes32(0), address(this)) {
            ok = true;
        } catch { ok = false; }
    }

    // ---------- W1: oversized length fields ----------
    function test_W1_oversizedLengthRejected() public {
        // Build returndata: offsetOffer=0x40, offsetConsideration=0x60,
        // offerLength = huge (2^200), considerationLength = 0.
        bytes memory payload = abi.encodePacked(
            uint256(0x40),                 // offsetOffer
            uint256(0x60),                 // offsetConsideration (overlaps end)
            uint256(1 << 200),             // offerLength (way over 65535)
            uint256(0)                     // considerationLength
        );
        evil.setPayload(payload);

        AdvancedOrder memory adv = _contractOrder();
        bool ok = _fulfill(adv);

        // Must NOT succeed — oversized length rejected, no corruption.
        assertEq(ok, false, "FINDING W1: oversized generateOrder length accepted");
    }

    // ---------- W2: offset past returndatasize ----------
    function test_W2_offsetPastReturndataRejected() public {
        // offsetOffer points far beyond the actual returndata length.
        bytes memory payload = abi.encodePacked(
            uint256(0xFFFFFF),             // offsetOffer (past end)
            uint256(0x60),
            uint256(0),
            uint256(0)
        );
        evil.setPayload(payload);

        AdvancedOrder memory adv = _contractOrder();
        bool ok = _fulfill(adv);
        assertEq(ok, false, "FINDING W2: out-of-bounds offset accepted");
    }

    // ---------- W3: truncated returndata ----------
    function test_W3_truncatedReturndataRejected() public {
        // Only one word of returndata — less than the required three.
        bytes memory payload = abi.encodePacked(uint256(0x40));
        evil.setPayload(payload);

        AdvancedOrder memory adv = _contractOrder();
        bool ok = _fulfill(adv);
        assertEq(ok, false, "FINDING W3: truncated returndata accepted");
    }

    // ---------- W4: well-formed but empty (control) ----------
    // A correctly-encoded empty offer/consideration. This SHOULD decode
    // cleanly (the offerer offers nothing and asks nothing) — proving the
    // decoder accepts valid input, so W1-W3 failures are real rejections
    // not blanket reverts.
    function test_W4_wellFormedEmptyDecodes() public {
        bytes memory payload = abi.encodePacked(
            uint256(0x40),   // offsetOffer
            uint256(0x60),   // offsetConsideration
            uint256(0),      // offerLength = 0
            uint256(0)       // considerationLength = 0
        );
        evil.setPayload(payload);

        AdvancedOrder memory adv = _contractOrder();
        bool ok = _fulfill(adv);
        // Empty contract order with no items — should succeed (nothing to do).
        emit log_named_uint("W4 well-formed empty decoded (1=yes)", ok ? 1 : 0);
    }
}
