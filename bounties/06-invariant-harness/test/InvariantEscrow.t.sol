// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {IMDWorksEscrow} from "../src/IMDWorksEscrow.sol";
import {MockToken} from "../src/MockToken.sol";
import {EscrowHandler, IEscrow} from "../src/EscrowHandler.sol";

/// @notice Invariant suite for the UNMODIFIED IMDWorksEscrow.
/// @dev Every expectation is derived from the handler's shadow model, which is built
///      only from the arguments this harness passed in - never read back from the
///      contract. See README for assumptions.
contract InvariantEscrowTest is Test {
    MockToken internal token;
    IMDWorksEscrow internal escrow;
    EscrowHandler internal handler;

    function setUp() public {
        token = new MockToken();
        escrow = new IMDWorksEscrow(address(token));
        handler = new EscrowHandler(IEscrow(address(escrow)), token);
        handler.seedOneSettledBounty();
        targetContract(address(handler));
    }

    // ---- independent liability recomputation ---------------------------------

    function invariant_totalLockedMatchesModel() public view {
        assertEq(escrow.totalLocked(), handler.shadowLocked(), "totalLocked != sum(shadow rewards of open bounties)");
    }

    function invariant_totalClaimableMatchesModel() public view {
        assertEq(escrow.totalClaimable(), handler.shadowCreditTotal(), "totalClaimable != sum(shadow credits)");
    }

    function invariant_liabilitiesEqualModel() public view {
        assertEq(
            escrow.liabilities(),
            handler.shadowLiabilities(),
            "liabilities() != shadowLocked + shadowCreditTotal"
        );
    }

    function invariant_balanceCoversLiabilities() public view {
        assertGe(
            token.balanceOf(address(escrow)),
            escrow.liabilities(),
            "escrow token balance does not cover outstanding liabilities"
        );
    }

    // ---- per-bounty and per-wallet reconciliation ----------------------------

    function invariant_claimableMatchesModelPerAccount() public view {
        uint256 n = handler.creatorsLength();
        for (uint256 i = 0; i < n; i++) {
            address a = handler.creators(i);
            assertEq(escrow.claimable(a), handler.shadowCredit(a), "claimable mismatch (creator)");
        }
        uint256 m = handler.workersLength();
        for (uint256 i = 0; i < m; i++) {
            address a = handler.workers(i);
            assertEq(escrow.claimable(a), handler.shadowCredit(a), "claimable mismatch (worker)");
        }
    }

    /// @notice A bounty is either unsettled (paid == 0) or paid exactly once (paid == reward).
    function invariant_noBountyPaysTwice() public view {
        uint256 n = handler.bountyCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 id = handler.bountyIdAt(i);
            uint256 reward = handler.shadowReward(id);
            uint256 paid = handler.shadowPaid(id);
            assertTrue(paid == 0 || paid == reward, "bounty paid more than once or a partial amount");
        }
    }

    /// @notice Rejections the model requires must actually be rejected by the contract.
    function invariant_noUnexpectedSuccesses() public view {
        assertEq(handler.ghost_unexpectedSuccesses(), 0, handler.lastUnexpectedAction());
    }

    // ---- reporting -----------------------------------------------------------

    function invariant_callSummary() public view {
        console.log("bountyIds", handler.bountyCount());
        console.log("actions", handler.ghost_actions());
        console.log("create", handler.ghost_createBounty());
        console.log("addReward", handler.ghost_addReward());
        console.log("submitWork", handler.ghost_submitWork());
        console.log("submitWorkFor", handler.ghost_submitWorkFor());
        console.log("award", handler.ghost_award());
        console.log("cancel", handler.ghost_cancel());
        console.log("expire", handler.ghost_expire());
        console.log("withdraw", handler.ghost_withdraw());
        console.log("payments", handler.ghost_payments());
        console.log("unexpectedSuccesses", handler.ghost_unexpectedSuccesses());
    }
}
