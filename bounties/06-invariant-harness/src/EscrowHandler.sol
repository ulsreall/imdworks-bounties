// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {MockToken} from "./MockToken.sol";

interface IEscrow {
    function createBounty(uint256 reward, uint64 deadline, bytes32 briefHash, string calldata briefURI)
        external
        returns (uint256 id);
    function addReward(uint256 id, uint256 amount) external;
    function setOperator(address operator, bool approved) external;
    function submitWork(uint256 id, bytes32 proofHash, string calldata proofURI) external;
    function submitWorkFor(uint256 id, address author, bytes32 proofHash, string calldata proofURI) external;
    function award(uint256 id, address winner) external;
    function cancel(uint256 id) external;
    function expire(uint256 id) external;
    function withdraw(address recipient) external;
    function claimable(address account) external view returns (uint256);
    function totalLocked() external view returns (uint256);
    function totalClaimable() external view returns (uint256);
    function liabilities() external view returns (uint256);
}

/// @notice Stateful action handler with a shadow accounting model.
/// @dev The shadow model is derived ONLY from the actions this handler performed and
///      from the values it passed in. It never reads escrow storage to compute
///      expectations (`totalLocked`, `totalClaimable`, `liabilities` are used only by
///      the invariants as the implementation values under test, never as the source of
///      truth for the model). Liabilities are therefore independently recomputed.
contract EscrowHandler is Test {
    IEscrow public immutable escrow;
    MockToken public immutable token;

    address[] public creators; // 3
    address[] public workers; // 5
    uint256[] public bountyIds;

    // ---- shadow model -------------------------------------------------------
    mapping(uint256 => uint256) public shadowReward; // create + addReward amounts
    mapping(uint256 => address) public shadowCreator;
    mapping(uint256 => uint8) public shadowStatus; // 1 open, 2 awarded, 3 cancelled, 4 expired
    mapping(uint256 => uint64) public shadowDeadline;
    mapping(uint256 => uint256) public shadowSubmissions;
    mapping(uint256 => mapping(address => bool)) public shadowSubmitted;
    mapping(uint256 => uint256) public shadowPaid; // credited for this bounty: 0 or reward
    mapping(address => uint256) public shadowCredit; // withdrawable credit per address
    uint256 public shadowLocked; // sum of rewards of open bounties
    uint256 public shadowCreditTotal; // sum of all credits

    mapping(uint256 => address) public shadowOperatorOf; // bounty-independent, informational

    // ---- ghosts -------------------------------------------------------------
    uint256 public ghost_actions;
    uint256 public ghost_createBounty;
    uint256 public ghost_addReward;
    uint256 public ghost_submitWork;
    uint256 public ghost_submitWorkFor;
    uint256 public ghost_award;
    uint256 public ghost_cancel;
    uint256 public ghost_expire;
    uint256 public ghost_withdraw;
    uint256 public ghost_payments;
    uint256 public ghost_unexpectedSuccesses;
    string public lastUnexpectedAction;

    constructor(IEscrow escrow_, MockToken token_) {
        escrow = escrow_;
        token = token_;

        for (uint256 i = 0; i < 3; i++) {
            address c = address(uint160(0xC000 + i));
            creators.push(c);
            token.mint(c, 1_000_000e6);
            vm.prank(c);
            token.approve(address(escrow), type(uint256).max);
        }
        for (uint256 i = 0; i < 5; i++) {
            workers.push(address(uint160(0xD000 + i)));
        }
    }

    // ---- helpers ------------------------------------------------------------

    function _r(uint256 seed, string memory tag) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(seed, tag)));
    }

    function _count() internal view returns (uint256) {
        return bountyIds.length;
    }

    function bountyCount() external view returns (uint256) {
        return bountyIds.length;
    }

    function bountyIdAt(uint256 i) external view returns (uint256) {
        return bountyIds[i];
    }

    function creatorsLength() external view returns (uint256) {
        return creators.length;
    }

    function workersLength() external view returns (uint256) {
        return workers.length;
    }

    /// @notice recomputed liabilities from model state
    function shadowLiabilities() external view returns (uint256) {
        return shadowLocked + shadowCreditTotal;
    }

    // ---- actions ------------------------------------------------------------

    /// @notice Deterministic, always-attempted lifecycle: create -> submit -> award.
    /// @dev Guarantees the harness reaches terminal states so that the negative
    ///      actions below have something to attack in every sequence.
    function seedOneSettledBounty() public {
        ghost_actions++;
        address c = creators[0];
        address w = workers[0];
        uint256 reward = 100e6;
        uint64 deadline = uint64(block.timestamp + 1 days);
        if (token.balanceOf(c) < reward) return;

        uint256 id;
        vm.prank(c);
        try escrow.createBounty(reward, deadline, bytes32(uint256(0xA11CE)), "ipfs://seeded") returns (uint256 newId) {
            id = newId;
        } catch {
            return;
        }
        bountyIds.push(id);
        shadowCreator[id] = c;
        shadowReward[id] = reward;
        shadowStatus[id] = 1;
        shadowDeadline[id] = deadline;
        shadowLocked += reward;
        ghost_createBounty++;

        vm.prank(w);
        try escrow.submitWork(id, bytes32(uint256(0xBEEF)), "ipfs://seeded-proof") {
            shadowSubmitted[id][w] = true;
            shadowSubmissions[id] += 1;
            ghost_submitWork++;
        } catch {
            return;
        }

        vm.prank(c);
        try escrow.award(id, w) {
            shadowStatus[id] = 2;
            shadowLocked -= reward;
            shadowPaid[id] = reward;
            shadowCredit[w] += reward;
            shadowCreditTotal += reward;
            ghost_award++;
            ghost_payments++;
        } catch {}
    }

    /// @notice The very first call the fuzzer makes: settle a bounty so mutations to
    ///         terminal-state handling are reachable immediately.
    function seedInitialState() external {
        if (bountyIds.length == 0) seedOneSettledBounty();
    }

    function createBounty(uint256 seed) external {
        ghost_actions++;
        uint256 r = _r(seed, "create");
        address creator = creators[r % creators.length];
        uint256 reward = (1 + (r % 500)) * 1e6; // 1 - 500 USDG (6dp)
        if (reward > token.balanceOf(creator)) return;
        uint64 deadline = uint64(block.timestamp + 1 hours + (r % 30 days));

        vm.prank(creator);
        try escrow.createBounty(reward, deadline, bytes32(r), "ipfs://brief") returns (uint256 id) {
            bountyIds.push(id);
            shadowCreator[id] = creator;
            shadowReward[id] = reward;
            shadowStatus[id] = 1;
            shadowDeadline[id] = deadline;
            shadowLocked += reward;
            ghost_createBounty++;
        } catch {}
    }

    function addReward(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "add");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (block.timestamp >= shadowDeadline[id]) return;
        address creator = creators[(r >> 8) % creators.length];
        uint256 amount = (1 + (r % 100)) * 1e6;
        if (token.balanceOf(creator) < amount) return;

        vm.prank(creator);
        try escrow.addReward(id, amount) {
            shadowReward[id] += amount;
            shadowLocked += amount;
            ghost_addReward++;
        } catch {}
    }

    function setOperator(uint256 seed) external {
        ghost_actions++;
        uint256 r = _r(seed, "op");
        address author = creators[r % creators.length];
        address operator = workers[(r >> 8) % workers.length];
        vm.prank(author);
        try escrow.setOperator(operator, true) {
            shadowOperatorOf[r % creators.length] = operator;
        } catch {}
    }

    function submitWork(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "submit");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (block.timestamp >= shadowDeadline[id]) return;
        address worker = workers[(r >> 8) % workers.length];
        vm.prank(worker);
        try escrow.submitWork(id, bytes32(r), "ipfs://proof") {
            if (!shadowSubmitted[id][worker]) {
                shadowSubmitted[id][worker] = true;
                shadowSubmissions[id] += 1;
            }
            ghost_submitWork++;
        } catch {}
    }

    function submitWorkFor(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "submitfor");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (block.timestamp >= shadowDeadline[id]) return;
        address author = creators[(r >> 8) % creators.length];
        address operator = shadowOperatorOf[(r >> 8) % creators.length];
        if (operator == address(0)) return;
        vm.prank(operator);
        try escrow.submitWorkFor(id, author, bytes32(r), "ipfs://proof") {
            if (!shadowSubmitted[id][author]) {
                shadowSubmitted[id][author] = true;
                shadowSubmissions[id] += 1;
            }
            ghost_submitWorkFor++;
        } catch {}
    }

    function award(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "award");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (block.timestamp >= uint256(shadowDeadline[id]) + 7 days) return;
        address creator = shadowCreator[id];
        address winner = workers[(r >> 16) % workers.length];
        if (!shadowSubmitted[id][winner]) {
            // create the precondition deterministically: the winner submits first
            vm.prank(winner);
            try escrow.submitWork(id, bytes32(r), "ipfs://proof") {
                shadowSubmitted[id][winner] = true;
                shadowSubmissions[id] += 1;
                ghost_submitWork++;
            } catch {}
            if (!shadowSubmitted[id][winner]) return;
        }

        vm.prank(creator);
        try escrow.award(id, winner) {
            shadowStatus[id] = 2;
            shadowLocked -= shadowReward[id];
            shadowPaid[id] = shadowReward[id];
            shadowCredit[winner] += shadowReward[id];
            shadowCreditTotal += shadowReward[id];
            ghost_award++;
            ghost_payments++;
        } catch {}
    }

    function cancel(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "cancel");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (shadowSubmissions[id] != 0) return;
        address creator = shadowCreator[id];
        vm.prank(creator);
        try escrow.cancel(id) {
            shadowStatus[id] = 3;
            shadowLocked -= shadowReward[id];
            shadowPaid[id] = shadowReward[id];
            shadowCredit[creator] += shadowReward[id];
            shadowCreditTotal += shadowReward[id];
            ghost_cancel++;
            ghost_payments++;
        } catch {}
    }

    function expire(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "expire");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        uint256 unlockAt = uint256(shadowDeadline[id]) + (shadowSubmissions[id] == 0 ? 0 : 7 days);
        if (block.timestamp < unlockAt) return;
        // anyone may expire; the refund always goes to the bounty's real creator
        address realCreator = shadowCreator[id];
        address caller = workers[(r >> 8) % workers.length];

        vm.prank(caller);
        try escrow.expire(id) {
            shadowStatus[id] = 4;
            shadowLocked -= shadowReward[id];
            shadowPaid[id] = shadowReward[id];
            shadowCredit[realCreator] += shadowReward[id];
            shadowCreditTotal += shadowReward[id];
            ghost_expire++;
            ghost_payments++;
        } catch {}
    }

    function withdraw(uint256 seed) external {
        ghost_actions++;
        uint256 r = _r(seed, "withdraw");
        address[] memory actors = new address[](8);
        for (uint256 i = 0; i < 3; i++) actors[i] = creators[i];
        for (uint256 i = 0; i < 5; i++) actors[3 + i] = workers[i];
        address actor = actors[r % 8];
        uint256 amount = shadowCredit[actor];
        if (amount == 0) return;
        address recipient = address(uint160(0xE000 + (r % 3)));

        vm.prank(actor);
        try escrow.withdraw(recipient) {
            shadowCredit[actor] -= amount;
            shadowCreditTotal -= amount;
            ghost_withdraw++;
        } catch {}
    }

    function warp(uint256 seed) external {
        ghost_actions++;
        uint256 r = _r(seed, "warp");
        vm.warp(block.timestamp + (r % 10 days) + 1 hours);
    }

    // ---- adversarial / negative actions -------------------------------------
    // These attempt state transitions the model says must be rejected. Any success
    // is recorded as a ghost failure, which is how mutations such as "award() does
    // not mark the bounty terminal" are detected even though the happy-path handler
    // would never attempt them.

    function tryAwardSettledBounty(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "neg-award");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] == 1) return; // only settled bounties
        address creator = shadowCreator[id];
        address winner = workers[(r >> 16) % workers.length];
        vm.prank(creator);
        try escrow.award(id, winner) {
            ghost_unexpectedSuccesses++;
            lastUnexpectedAction = "award() succeeded on a settled bounty";
        } catch {}
    }

    function tryExpireOpenBounty(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "neg-expire");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        uint256 unlockAt = uint256(shadowDeadline[id]) + (shadowSubmissions[id] == 0 ? 0 : 7 days);
        if (block.timestamp >= unlockAt) return; // only genuinely early calls
        address creator = creators[(r >> 8) % creators.length];
        vm.prank(creator);
        try escrow.expire(id) {
            ghost_unexpectedSuccesses++;
            lastUnexpectedAction = "expire() succeeded before the deadline window";
        } catch {}
    }

    function trySubmitAfterDeadline(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "neg-submit");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (block.timestamp < shadowDeadline[id]) return; // only after the deadline
        address worker = workers[(r >> 8) % workers.length];
        vm.prank(worker);
        try escrow.submitWork(id, bytes32(r), "ipfs://late") {
            ghost_unexpectedSuccesses++;
            lastUnexpectedAction = "submitWork() accepted after the deadline";
        } catch {}
    }

    function tryCancelWithSubmissions(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "neg-cancel");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (shadowSubmissions[id] == 0) return; // only bounties that have work
        address creator = creators[(r >> 8) % creators.length];
        vm.prank(creator);
        try escrow.cancel(id) {
            ghost_unexpectedSuccesses++;
            lastUnexpectedAction = "cancel() succeeded with submissions present";
        } catch {}
    }

    function tryWithdrawUnauthorized(uint256 seed) external {
        ghost_actions++;
        uint256 r = _r(seed, "neg-withdraw");
        address actor = workers[r % workers.length];
        if (shadowCredit[actor] != 0) return; // only accounts with no credit
        vm.prank(actor);
        try escrow.withdraw(actor) {
            ghost_unexpectedSuccesses++;
            lastUnexpectedAction = "withdraw() succeeded with zero credit";
        } catch {}
    }

    function trySubmitAsCreator(uint256 seed) external {
        ghost_actions++;
        if (_count() == 0) return;
        uint256 r = _r(seed, "neg-creator-submit");
        uint256 id = bountyIds[r % _count()];
        if (shadowStatus[id] != 1) return;
        if (block.timestamp >= shadowDeadline[id]) return;
        address creator = shadowCreator[id];
        vm.prank(creator);
        try escrow.submitWork(id, bytes32(r), "ipfs://self") {
            ghost_unexpectedSuccesses++;
            lastUnexpectedAction = "creator submitted work to their own bounty";
        } catch {}
    }
}
