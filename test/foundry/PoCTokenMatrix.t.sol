// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * Pathological-token compatibility matrix for Seaport 1.6.
 *
 * Real-world tokens deviate from the ERC20/721/1155 standards in many ways.
 * Seaport assumes specific behavior — does it stay safe when assumptions
 * break?
 *
 * Each probe builds an order using a pathological token and asks: does
 * Seaport detect the misbehavior, or does it leak value?
 *
 *  T1: SilentNoOpERC20 — transferFrom returns true but does nothing.
 *      Risk: Seaport thinks transfer succeeded; buyer pays but gets nothing.
 *
 *  T2: FeeOnTransferERC20 — takes 5% on every transfer.
 *      Risk: maker offers 100; only 95 arrives at buyer; Seaport unaware.
 *
 *  T3: DoubleTransferERC20 — transfers 2x the requested amount.
 *      Risk: maker drained 2x; allowance only debited 1x.
 *
 *  T4: NonStandardReturnERC20 — returns 2 instead of 1.
 *      Risk: should be rejected (Seaport checks for exactly 1).
 *
 *  T5: HugeReturndataERC20 — returns 1 plus 100KB of garbage.
 *      Risk: returndata-bomb griefing the caller.
 *
 *  T6: ReentrantERC20 — transferFrom calls back into Seaport.
 *      Risk: cross-token reentrancy bypass.
 *
 *  T7: DoubleSpendableERC721 — ownerOf returns old owner after transferFrom.
 *      Risk: maker can re-list the same NFT after sale.
 */

import { OrderType, ItemType } from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    Order,
    OrderComponents,
    OrderParameters
} from "seaport-types/src/lib/ConsiderationStructs.sol";
import { BaseOrderTest } from "./utils/BaseOrderTest.sol";

// ---- Pathological tokens ----

contract SilentNoOpERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 18;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // SILENT NO-OP: returns true, doesn't actually move anything
    function transferFrom(address, address, uint256) external pure returns (bool) {
        return true;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
}

contract FeeOnTransferERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 18;
    uint256 constant FEE_BPS = 500; // 5%

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        if (msg.sender != from) {
            require(allowance[from][msg.sender] >= amount, "allow");
            allowance[from][msg.sender] -= amount;
        }
        uint256 fee = (amount * FEE_BPS) / 10000;
        balanceOf[from] -= amount;
        balanceOf[to] += (amount - fee);
        // fee is burned
        return true;
    }
}

contract DoubleTransferERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 18;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        // Maliciously transfer 2x what was requested
        uint256 actual = amount * 2;
        require(balanceOf[from] >= actual, "bal");
        if (msg.sender != from) {
            require(allowance[from][msg.sender] >= amount, "allow");
            allowance[from][msg.sender] -= amount; // only decrement by requested
        }
        balanceOf[from] -= actual;
        balanceOf[to] += actual;
        return true;
    }
}

contract NonStandardReturnERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 18;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // Returns 2 instead of 1 — Seaport's check is "exactly 1"
    function transferFrom(address from, address to, uint256 amount) external returns (uint256) {
        require(balanceOf[from] >= amount, "bal");
        if (msg.sender != from) {
            require(allowance[from][msg.sender] >= amount, "allow");
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return 2; // non-standard
    }
}

contract DoubleSpendableERC721 {
    mapping(uint256 => address) internal _owner;
    mapping(address => mapping(address => bool)) internal _approvedForAll;

    function mint(address to, uint256 id) external {
        _owner[id] = to;
    }

    function ownerOf(uint256 id) external view returns (address) {
        return _owner[id];
    }

    function setApprovalForAll(address op, bool approved) external {
        _approvedForAll[msg.sender][op] = approved;
    }

    function isApprovedForAll(address o, address op) external view returns (bool) {
        return _approvedForAll[o][op];
    }

    function getApproved(uint256) external pure returns (address) {
        return address(0);
    }

    // EVIL: doesn't update _owner mapping
    function transferFrom(address, address, uint256) external {
        // returns success but ownerOf still points to old owner
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == 0x80ac58cd || i == 0x01ffc9a7;
    }
}

contract PoCTokenMatrix is BaseOrderTest {
    receive() external payable override {}

    // Helper to build an order: alice offers `offerToken/offerAmount` for
    // `priceWei` ETH, signed with alicePk.
    function _buildEthOrder(address offerToken, uint256 offerAmount, uint256 priceWei)
        internal
        returns (Order memory order)
    {
        offerItems.push();
        offerItems[0].itemType = ItemType.ERC20;
        offerItems[0].token = offerToken;
        offerItems[0].identifierOrCriteria = 0;
        offerItems[0].startAmount = offerAmount;
        offerItems[0].endAmount = offerAmount;

        considerationItems.push();
        considerationItems[0].itemType = ItemType.NATIVE;
        considerationItems[0].startAmount = priceWei;
        considerationItems[0].endAmount = priceWei;
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
        order = Order(baseOrderParameters, sig);
    }

    // ---------- T1: SilentNoOpERC20 ----------
    // OBSERVATION (not a Seaport bounty finding): A malicious ERC20 whose
    // transferFrom returns `true` without actually transferring will satisfy
    // Seaport's success check. The buyer pays consideration, receives nothing.
    //
    // This is the documented threat model of any open marketplace that
    // accepts arbitrary token contracts (Uniswap, OpenSea, Blur, Seaport).
    // The attack requires the victim to choose to fill an order specifying
    // an attacker-deployed token — which is "user interaction with attacker
    // controlled content," explicitly excluded by Seaport's bounty scope.
    //
    // Mitigations exist OUTSIDE the protocol layer:
    //   - Wallet-level simulation (Tenderly, Blockaid)
    //   - Marketplace token allowlists
    //   - Buyer education
    //
    // This test ASSERTS the observed behavior so it can be tracked if the
    // design ever changes.
    function test_T1_silentNoOpERC20_documentedRisk() public {
        SilentNoOpERC20 tok = new SilentNoOpERC20();
        tok.mint(alice, 1000);
        vm.prank(alice);
        tok.approve(address(consideration), type(uint256).max);

        Order memory order = _buildEthOrder(address(tok), 100, 1 ether);

        uint256 buyerBefore = tok.balanceOf(address(this));
        uint256 aliceEthBefore = alice.balance;

        consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0));

        uint256 buyerAfter = tok.balanceOf(address(this));
        uint256 aliceEthAfter = alice.balance;

        // Documented behavior: fill succeeds, buyer received 0 tokens,
        // alice received full ETH.
        assertEq(buyerAfter - buyerBefore, 0, "T1: buyer receives nothing (documented)");
        assertEq(aliceEthAfter - aliceEthBefore, 1 ether, "T1: alice receives full payment (documented)");
    }

    // ---------- T2: FeeOnTransferERC20 ----------
    function test_T2_feeOnTransferERC20() public {
        FeeOnTransferERC20 tok = new FeeOnTransferERC20();
        tok.mint(alice, 1000);
        vm.prank(alice);
        tok.approve(address(consideration), type(uint256).max);

        Order memory order = _buildEthOrder(address(tok), 100, 1 ether);

        uint256 buyerBefore = tok.balanceOf(address(this));
        bool filled;
        try consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0)) {
            filled = true;
        } catch { filled = false; }
        uint256 buyerAfter = tok.balanceOf(address(this));

        emit log_named_uint("T2 filled (1=yes)", filled ? 1 : 0);
        emit log_named_uint("T2 buyer received (expected 100)", buyerAfter - buyerBefore);

        // T2 OBSERVATION: not necessarily a bug. Both parties signed up for
        // the FoT token. But document the under-delivery as informational.
        if (filled) {
            assertLt(buyerAfter - buyerBefore, 100, "T2: FoT under-delivered (informational)");
        }
    }

    // ---------- T3: DoubleTransferERC20 ----------
    function test_T3_doubleTransferERC20() public {
        DoubleTransferERC20 tok = new DoubleTransferERC20();
        tok.mint(alice, 1000);
        vm.prank(alice);
        tok.approve(address(consideration), type(uint256).max);

        Order memory order = _buildEthOrder(address(tok), 100, 1 ether);

        uint256 aliceTokenBefore = tok.balanceOf(alice);
        bool filled;
        try consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0)) {
            filled = true;
        } catch { filled = false; }
        uint256 aliceTokenAfter = tok.balanceOf(alice);

        emit log_named_uint("T3 filled (1=yes)", filled ? 1 : 0);
        emit log_named_uint("T3 alice tokens lost", aliceTokenBefore - aliceTokenAfter);

        // FINDING if: filled=true AND alice lost 200 tokens (double-transfer)
        // for an order specifying 100. That means token misbehavior was
        // undetected.
        bool isDangerous = filled && (aliceTokenBefore - aliceTokenAfter > 100);
        if (isDangerous) {
            emit log("T3: maker drained 2x via malicious token (informational - maker's choice)");
        }
        // This is informational. Token misbehavior is the token's bug, not
        // Seaport's, but worth knowing.
    }

    // ---------- T4: NonStandardReturnERC20 (returns 2 instead of 1) ----------
    function test_T4_nonStandardReturnERC20() public {
        NonStandardReturnERC20 tok = new NonStandardReturnERC20();
        tok.mint(alice, 1000);
        vm.prank(alice);
        tok.approve(address(consideration), type(uint256).max);

        Order memory order = _buildEthOrder(address(tok), 100, 1 ether);

        bool filled;
        try consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0)) {
            filled = true;
        } catch { filled = false; }

        emit log_named_uint("T4 filled (1=yes)", filled ? 1 : 0);
        // Seaport checks for return == 1. A token returning 2 should be rejected.
        assertEq(filled, false, "FINDING T4: non-standard return value (2) accepted by Seaport");
    }

    // ---------- T7: DoubleSpendableERC721 (same class as T1) ----------
    // OBSERVATION (not a Seaport bounty finding): A malicious ERC721 whose
    // transferFrom is a no-op satisfies Seaport's call-succeeded check.
    // Buyer pays, NFT does not transfer. Same caveat-emptor class as T1.
    function test_T7_doubleSpendable721_documentedRisk() public {
        DoubleSpendableERC721 tok = new DoubleSpendableERC721();
        tok.mint(alice, 700);
        vm.prank(alice);
        tok.setApprovalForAll(address(consideration), true);

        // Build a 721 ETH order
        offerItems.push();
        offerItems[0].itemType = ItemType.ERC721;
        offerItems[0].token = address(tok);
        offerItems[0].identifierOrCriteria = 700;
        offerItems[0].startAmount = 1;
        offerItems[0].endAmount = 1;
        considerationItems.push();
        considerationItems[0].itemType = ItemType.NATIVE;
        considerationItems[0].startAmount = 1 ether;
        considerationItems[0].endAmount = 1 ether;
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

        uint256 aliceEthBefore = alice.balance;
        consideration.fulfillOrder{ value: 1 ether }(order, bytes32(0));
        uint256 aliceEthAfter = alice.balance;

        // Documented behavior: fill succeeds, NFT stays with alice, alice
        // receives full ETH. Same class as T1.
        assertEq(tok.ownerOf(700), alice, "T7: NFT unchanged (documented)");
        assertEq(aliceEthAfter - aliceEthBefore, 1 ether, "T7: alice receives full payment (documented)");
    }
}
