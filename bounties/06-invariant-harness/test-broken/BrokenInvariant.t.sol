// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {BrokenEscrow} from "../broken/BrokenEscrow.sol";
import {MockToken} from "../src/MockToken.sol";
import {EscrowHandler, IEscrow} from "../src/EscrowHandler.sol";

/// @notice The SAME handler and invariants, pointed at a deliberately broken local
///         mutation (award() does not mark the bounty terminal). This suite MUST fail;
///         that is the proof that the harness detects the mutation.
contract BrokenInvariantTest is Test {
    MockToken internal token;
    BrokenEscrow internal escrow;
    EscrowHandler internal handler;

    function setUp() public {
        token = new MockToken();
        escrow = new BrokenEscrow(address(token));
        handler = new EscrowHandler(IEscrow(address(escrow)), token);
        handler.seedOneSettledBounty();
        targetContract(address(handler));
    }

    function invariant_liabilitiesEqualModel() public view {
        assertEq(escrow.liabilities(), handler.shadowLiabilities(), "liabilities != model");
    }

    function invariant_balanceCoversLiabilities() public view {
        assertGe(token.balanceOf(address(escrow)), escrow.liabilities(), "balance < liabilities");
    }

    function invariant_noBountyPaysTwice() public view {
        uint256 n = handler.bountyCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 id = handler.bountyIdAt(i);
            uint256 reward = handler.shadowReward(id);
            uint256 paid = handler.shadowPaid(id);
            assertTrue(paid == 0 || paid == reward, "bounty paid more than once");
        }
    }

    function invariant_noUnexpectedSuccesses() public view {
        assertEq(handler.ghost_unexpectedSuccesses(), 0, handler.lastUnexpectedAction());
    }
}
