// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {IMDWorksEscrow} from "../src/IMDWorksEscrow.sol";
import {
    StandardToken,
    PausedToken,
    SenderRestrictedToken,
    RecipientRestrictedToken,
    ReturnFalseToken,
    NoReturnToken,
    FeeOnTransferToken,
    ReentrantToken
} from "../src/Tokens.sol";

/// @notice Behaviour matrix for issuer restrictions against the UNMODIFIED escrow.
///         Every row is produced by an executable test; results are written to
///         results/*.json for aggregation into the published matrix.
contract IssuerRestrictionsTest is Test {
    address internal constant CREATOR = address(0xC0FFEE);
    address internal constant WORKER = address(0xB0B);
    address internal constant PAYEE = address(0xBEEF);
    address internal constant OTHER = address(0xA11CE);

    uint256 internal constant REWARD = 1_000_000; // 1.000000 (6dp)

    // ---------------------------------------------------------------- helpers

    function _emit(string memory mode, string memory body) internal {
        vm.writeFile(string.concat("results/mode-", mode, ".json"), body);
    }

    function _row(
        string memory mode,
        string memory deposit,
        string memory bookkeeping,
        string memory withdraw,
        bool creditPreserved,
        bool issuerActionRequired,
        bool supported
    ) internal pure returns (string memory) {
        return string.concat(
            '{"mode":"', mode,
            '","deposit":"', deposit,
            '","award_refund_while_restricted":"', bookkeeping,
            '","withdraw":"', withdraw,
            '","failed_withdraw_preserves_credit":', creditPreserved ? "true" : "false",
            ',"recovery_requires_issuer_action":', issuerActionRequired ? "true" : "false",
            ',"class":"', supported ? "supported" : "unsupported",
            '"}'
        );
    }

    function _fundAndSubmit(IMDWorksEscrow esc, address token, uint256 id) internal {
        vm.prank(CREATOR);
        StandardToken(token).approve(address(esc), type(uint256).max);
        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(1)), "ipfs://proof");
    }

    // ------------------------------------------------------ 1. standard token

    function test_mode_standard_exact_transfers_supported() public {
        StandardToken tok = new StandardToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);

        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");

        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");
        vm.prank(CREATOR);
        esc.award(id, WORKER);

        assertEq(esc.claimable(WORKER), REWARD, "winner credited");
        vm.prank(WORKER);
        esc.withdraw(PAYEE);
        assertEq(tok.balanceOf(PAYEE), REWARD, "payee received the full amount");

        // balance conservation
        assertEq(tok.balanceOf(address(esc)), esc.liabilities(), "balance == liabilities");
        assertEq(esc.liabilities(), 0, "nothing outstanding");

        _emit("01-standard", _row("standard-exact-6dp", "accepted", "n/a", "succeeds", true, false, true));
    }

    // ------------------------------------------------------- 2. paused token

    function test_mode_paused_deposit_blocked_and_payout_blocked() public {
        PausedToken tok = new PausedToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);

        tok.setPaused(true);
        vm.prank(CREATOR);
        vm.expectRevert(bytes("TOKEN_PAUSED"));
        esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");

        tok.setPaused(false);
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");
        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");

        // payout side: pause again
        tok.setPaused(true);

        // bookkeeping still works while paused: award moves credit, not tokens
        vm.prank(CREATOR);
        esc.award(id, WORKER);
        assertEq(esc.claimable(WORKER), REWARD, "award bookkeeping works while paused");
        assertEq(esc.totalLocked(), 0, "locked released while paused");

        // withdrawal fails, credit is preserved
        vm.prank(WORKER);
        vm.expectRevert(bytes("TOKEN_PAUSED"));
        esc.withdraw(PAYEE);
        assertEq(esc.claimable(WORKER), REWARD, "failed withdraw preserves credit");
        assertEq(tok.balanceOf(address(esc)), REWARD, "tokens still escrowed");

        // recovery requires issuer action (unpause)
        tok.setPaused(false);
        vm.prank(WORKER);
        esc.withdraw(PAYEE);
        assertEq(tok.balanceOf(PAYEE), REWARD, "recovery after issuer unpause");
        assertEq(tok.balanceOf(address(esc)), esc.liabilities(), "conservation after recovery");

        _emit(
            "02-paused",
            _row("paused-transfers", "blocked (TOKEN_PAUSED)", "works while paused", "blocked, credit preserved", true, true, false)
        );
    }

    function test_mode_paused_refund_bookkeeping_works() public {
        PausedToken tok = new PausedToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 hours), bytes32(uint256(1)), "ipfs://b");

        vm.warp(block.timestamp + 2 hours);
        tok.setPaused(true);

        // refund bookkeeping (expire) does not move tokens -> succeeds while paused
        vm.prank(OTHER);
        esc.expire(id);
        assertEq(esc.claimable(CREATOR), REWARD, "refund credited while paused");
        assertEq(esc.totalLocked(), 0, "locked released");

        vm.prank(CREATOR);
        vm.expectRevert(bytes("TOKEN_PAUSED"));
        esc.withdraw(CREATOR);
        assertEq(esc.claimable(CREATOR), REWARD, "credit preserved on failed refund withdrawal");
    }

    // -------------------------------------------- 3. sender-restricted token

    function test_mode_sender_restricted_creator() public {
        SenderRestrictedToken tok = new SenderRestrictedToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);

        tok.setBlockedSender(CREATOR, true);
        vm.prank(CREATOR);
        vm.expectRevert(bytes("SENDER_BLOCKED"));
        esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");

        // a non-blocked address can still fund a bounty (no issuer action needed)
        tok.mint(OTHER, 10 * REWARD);
        vm.prank(OTHER);
        tok.approve(address(esc), type(uint256).max);
        vm.prank(OTHER);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");
        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");
        vm.prank(OTHER);
        esc.award(id, WORKER);

        // the blocked creator cannot pay out; a non-blocked winner can receive
        vm.prank(WORKER);
        esc.withdraw(PAYEE);
        assertEq(tok.balanceOf(PAYEE), REWARD, "unblocked payout path works");
        assertEq(tok.balanceOf(address(esc)), esc.liabilities(), "conservation");

        _emit(
            "03-sender-restricted",
            _row("creator-on-sender-blocklist", "blocked (SENDER_BLOCKED)", "works", "blocked only if blocked address is the sender", true, true, false)
        );
    }

    // ----------------------------------------- 4. recipient-restricted token

    function test_mode_recipient_restricted_winner_can_redirect() public {
        RecipientRestrictedToken tok = new RecipientRestrictedToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");
        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");
        vm.prank(CREATOR);
        esc.award(id, WORKER);

        // block the worker itself as a recipient
        tok.setBlockedRecipient(WORKER, true);
        vm.prank(WORKER);
        vm.expectRevert(bytes("RECIPIENT_BLOCKED"));
        esc.withdraw(WORKER);
        assertEq(esc.claimable(WORKER), REWARD, "credit preserved when recipient blocked");

        // the creditor chooses a different recipient: recovery WITHOUT issuer action
        vm.prank(WORKER);
        esc.withdraw(PAYEE);
        assertEq(tok.balanceOf(PAYEE), REWARD, "redirected payout succeeded");
        assertEq(tok.balanceOf(address(esc)), esc.liabilities(), "conservation");

        _emit(
            "04-recipient-restricted",
            _row("winner-on-recipient-blocklist", "accepted", "works", "blocked to blocked recipient, redirect allowed", true, false, true)
        );
    }

    // -------------------------------------------------- 5. return-false token

    function test_mode_return_false_is_treated_as_revert() public {
        ReturnFalseToken tok = new ReturnFalseToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);

        tok.setFail(true);
        vm.prank(CREATOR);
        vm.expectRevert();
        esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");

        tok.setFail(false);
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");
        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");
        vm.prank(CREATOR);
        esc.award(id, WORKER);

        tok.setFail(true);
        vm.prank(WORKER);
        vm.expectRevert();
        esc.withdraw(PAYEE);
        assertEq(esc.claimable(WORKER), REWARD, "credit preserved on false-return transfer");

        tok.setFail(false);
        vm.prank(WORKER);
        esc.withdraw(PAYEE);
        assertEq(tok.balanceOf(PAYEE), REWARD, "recovery once the token returns true");

        _emit(
            "05-return-false",
            _row("returns-false", "blocked", "works", "blocked, credit preserved", true, true, false)
        );
    }

    // ----------------------------------------------------- 6. no-return token

    function test_mode_no_return_value_supported() public {
        NoReturnToken tok = new NoReturnToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");
        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");
        vm.prank(CREATOR);
        esc.award(id, WORKER);
        vm.prank(WORKER);
        esc.withdraw(PAYEE);

        assertEq(tok.balanceOf(PAYEE), REWARD, "no-return token fully supported");
        assertEq(tok.balanceOf(address(esc)), esc.liabilities(), "conservation");

        _emit("06-no-return", _row("no-return-values", "accepted", "works", "succeeds", true, false, true));
    }

    // ----------------------------------------------- 7. fee-on-transfer token

    function test_mode_fee_on_transfer_unsupported_but_credit_safe() public {
        FeeOnTransferToken tok = new FeeOnTransferToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);

        // deposit is rejected by the exact-balance check: the escrow would otherwise
        // under-collateralise every bounty
        tok.setFeeBps(100);
        vm.prank(CREATOR);
        vm.expectRevert(IMDWorksEscrow.UnsupportedTransfer.selector);
        esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");

        // with fees off, the lifecycle works; switching fees on makes payouts fail safely
        tok.setFeeBps(0);
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");
        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");
        vm.prank(CREATOR);
        esc.award(id, WORKER);

        tok.setFeeBps(100);
        vm.prank(WORKER);
        vm.expectRevert(IMDWorksEscrow.UnsupportedTransfer.selector);
        esc.withdraw(PAYEE);
        assertEq(esc.claimable(WORKER), REWARD, "credit preserved despite fee-on-transfer payout");
        assertEq(tok.balanceOf(address(esc)), REWARD, "escrow still holds the full reward");

        tok.setFeeBps(0);
        vm.prank(WORKER);
        esc.withdraw(PAYEE);
        assertEq(tok.balanceOf(PAYEE), REWARD, "recovery when the fee is removed (issuer action)");

        _emit(
            "07-fee-on-transfer",
            _row("fee-on-transfer", "rejected (UnsupportedTransfer)", "works", "rejected (UnsupportedTransfer), credit preserved", true, true, false)
        );
    }

    // ------------------------------------------------------- 8. callback token

    function test_mode_callback_token_reentrancy_blocked() public {
        ReentrantToken tok = new ReentrantToken();
        IMDWorksEscrow esc = new IMDWorksEscrow(address(tok));
        tok.mint(CREATOR, 10 * REWARD);
        vm.prank(CREATOR);
        tok.approve(address(esc), type(uint256).max);
        tok.configure(address(esc), true);

        // deposit path: transferFrom fires the hook, which tries withdraw() and award()
        vm.prank(CREATOR);
        uint256 id = esc.createBounty(REWARD, uint64(block.timestamp + 1 days), bytes32(uint256(1)), "ipfs://b");
        assertGt(tok.callbackAttempts(), 0, "callback fired during deposit");
        assertFalse(tok.outerTransferSucceeded(), "callback could not move funds");
        assertEq(esc.claimable(address(tok)), 0, "token contract gained no credit");
        assertEq(esc.totalLocked(), REWARD, "locked amount unchanged by the callback");

        vm.prank(WORKER);
        esc.submitWork(id, bytes32(uint256(2)), "ipfs://p");
        vm.prank(CREATOR);
        esc.award(id, WORKER);

        // payout path: transfer fires the hook again
        uint256 attemptsBefore = tok.callbackAttempts();
        vm.prank(WORKER);
        esc.withdraw(PAYEE);
        assertGt(tok.callbackAttempts(), attemptsBefore, "callback fired during payout");
        assertFalse(tok.outerTransferSucceeded(), "re-entrant calls remained blocked");
        assertEq(tok.balanceOf(PAYEE), REWARD, "outer transfer completed correctly");

        // balance conservation after a reentrancy attempt
        assertEq(tok.balanceOf(address(esc)), esc.liabilities(), "conservation after reentrancy attempt");
        assertEq(esc.liabilities(), 0, "no residual liabilities");

        _emit(
            "08-callback-reentrancy",
            _row("erc777-style-callback", "accepted, hook re-entry blocked", "works", "accepted, re-entry blocked", true, false, true)
        );
    }
}
