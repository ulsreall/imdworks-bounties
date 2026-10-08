// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title IMD Works bounty escrow
/// @notice Creator-judged bounties funded in one immutable ERC-20 asset (USDG).
/// @dev No administrator, upgrades, fees, arbitration, or privileged withdrawals.
///      Only standard, non-rebasing tokens with exact transfers are supported.
contract IMDWorksEscrow is ReentrancyGuard {
    using SafeERC20 for IERC20;

    enum Status { Missing, Open, Awarded, Cancelled, Expired }

    struct Bounty {
        address creator;
        address winner;
        uint64 deadline;
        uint64 submissions;
        Status status;
        uint256 reward;
        bytes32 briefHash;
    }

    struct Submission {
        bytes32 proofHash;
        uint64 updatedAt;
    }

    IERC20 public immutable paymentToken;
    uint256 public constant MIN_DURATION = 1 hours;
    uint256 public constant MAX_DURATION = 90 days;
    uint256 public constant REVIEW_PERIOD = 7 days;
    uint256 public constant MAX_URI_BYTES = 512;
    uint256 public nextBountyId = 1;
    uint256 public totalLocked;
    uint256 public totalClaimable;

    mapping(uint256 => Bounty) public bounties;
    mapping(uint256 => mapping(address => Submission)) public submissions;
    mapping(address => uint256) public claimable;
    mapping(address => mapping(address => bool)) public operators;

    error InvalidToken();
    error InvalidAmount();
    error InvalidDeadline();
    error InvalidMetadata();
    error InvalidRecipient();
    error InvalidOperator();
    error NotAuthorized();
    error NotOpen();
    error SubmissionClosed();
    error ReviewClosed();
    error HasSubmissions();
    error MissingSubmission();
    error TooEarly();
    error UnsupportedTransfer();

    event BountyCreated(uint256 indexed bountyId, address indexed creator, uint256 reward, uint64 deadline, bytes32 briefHash, string briefURI);
    event RewardAdded(uint256 indexed bountyId, uint256 amount, uint256 reward);
    event WorkSubmitted(uint256 indexed bountyId, address indexed author, address indexed operator, bytes32 proofHash, string proofURI);
    event BountyAwarded(uint256 indexed bountyId, address indexed winner, uint256 amount);
    event BountyRefunded(uint256 indexed bountyId, address indexed creator, uint256 amount, Status status);
    event Withdrawn(address indexed account, address indexed recipient, uint256 amount);
    event OperatorSet(address indexed account, address indexed operator, bool approved);

    constructor(address token) {
        if (token.code.length == 0) revert InvalidToken();
        paymentToken = IERC20(token);
        // Fail early for contracts that do not expose the ERC-20 balance interface.
        IERC20(token).balanceOf(address(this));
    }

    /// @notice Deposit the exact reward. The brief and deadline cannot be changed.
    /// @param briefHash Keccak-256 of the canonical UTF-8 bounty brief.
    function createBounty(uint256 reward, uint64 deadline, bytes32 briefHash, string calldata briefURI)
        external nonReentrant returns (uint256 id)
    {
        if (reward == 0) revert InvalidAmount();
        if (deadline < block.timestamp + MIN_DURATION || deadline > block.timestamp + MAX_DURATION) revert InvalidDeadline();
        _metadata(briefHash, briefURI);
        id = nextBountyId++;
        bounties[id] = Bounty(msg.sender, address(0), deadline, 0, Status.Open, reward, briefHash);
        totalLocked += reward;
        _deposit(reward);
        emit BountyCreated(id, msg.sender, reward, deadline, briefHash, briefURI);
    }

    function addReward(uint256 id, uint256 amount) external nonReentrant {
        Bounty storage b = _open(id);
        if (b.creator != msg.sender) revert NotAuthorized();
        if (block.timestamp >= b.deadline) revert SubmissionClosed();
        if (amount == 0) revert InvalidAmount();
        b.reward += amount;
        totalLocked += amount;
        _deposit(amount);
        emit RewardAdded(id, amount, b.reward);
    }

    /// @notice An operator can submit proof, but cannot award or withdraw funds.
    function setOperator(address operator, bool approved) external {
        if (operator == address(0) || operator == msg.sender || operator == address(this)) revert InvalidOperator();
        operators[msg.sender][operator] = approved;
        emit OperatorSet(msg.sender, operator, approved);
    }

    function submitWork(uint256 id, bytes32 proofHash, string calldata proofURI) external {
        _submit(id, msg.sender, proofHash, proofURI);
    }

    function submitWorkFor(uint256 id, address author, bytes32 proofHash, string calldata proofURI) external {
        if (!operators[author][msg.sender]) revert NotAuthorized();
        _submit(id, author, proofHash, proofURI);
    }

    /// @notice Select one submitted author. Their reward becomes withdrawable.
    /// @dev Selection is creator-controlled; the contract does not judge work quality.
    function award(uint256 id, address winner) external nonReentrant {
        Bounty storage b = _open(id);
        if (b.creator != msg.sender) revert NotAuthorized();
        if (block.timestamp >= uint256(b.deadline) + REVIEW_PERIOD) revert ReviewClosed();
        if (submissions[id][winner].proofHash == bytes32(0)) revert MissingSubmission();
        b.status = Status.Awarded;
        b.winner = winner;
        _credit(winner, b.reward);
        emit BountyAwarded(id, winner, b.reward);
    }

    /// @notice Cancel only while there are no submissions.
    function cancel(uint256 id) external nonReentrant {
        Bounty storage b = _open(id);
        if (b.creator != msg.sender) revert NotAuthorized();
        if (b.submissions != 0) revert HasSubmissions();
        _refund(id, b, Status.Cancelled);
    }

    /// @notice Anyone can release an expired bounty back to its creator.
    /// @dev Submitted work receives a seven-day review window. No winner means refund.
    function expire(uint256 id) external nonReentrant {
        Bounty storage b = _open(id);
        uint256 unlockAt = uint256(b.deadline) + (b.submissions == 0 ? 0 : REVIEW_PERIOD);
        if (block.timestamp < unlockAt) revert TooEarly();
        _refund(id, b, Status.Expired);
    }

    /// @notice Withdraw the caller's entire credit to a chosen recipient.
    /// @dev A failed token transfer reverts without losing the caller's credit.
    function withdraw(address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert InvalidRecipient();
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert InvalidAmount();
        claimable[msg.sender] = 0;
        totalClaimable -= amount;
        uint256 beforeSelf = paymentToken.balanceOf(address(this));
        uint256 beforeRecipient = paymentToken.balanceOf(recipient);
        paymentToken.safeTransfer(recipient, amount);
        uint256 afterSelf = paymentToken.balanceOf(address(this));
        uint256 afterRecipient = paymentToken.balanceOf(recipient);
        if (afterSelf > beforeSelf || beforeSelf - afterSelf != amount || afterRecipient < beforeRecipient || afterRecipient - beforeRecipient != amount) revert UnsupportedTransfer();
        emit Withdrawn(msg.sender, recipient, amount);
    }

    function liabilities() external view returns (uint256) {
        return totalLocked + totalClaimable;
    }

    function _open(uint256 id) private view returns (Bounty storage b) {
        b = bounties[id];
        if (b.status != Status.Open) revert NotOpen();
    }

    function _metadata(bytes32 hash, string calldata uri) private pure {
        if (hash == bytes32(0) || bytes(uri).length == 0 || bytes(uri).length > MAX_URI_BYTES) revert InvalidMetadata();
    }

    function _submit(uint256 id, address author, bytes32 hash, string calldata uri) private {
        Bounty storage b = _open(id);
        if (author == b.creator || author == address(0) || author == address(this)) revert NotAuthorized();
        if (block.timestamp >= b.deadline) revert SubmissionClosed();
        _metadata(hash, uri);
        if (submissions[id][author].proofHash == bytes32(0)) b.submissions++;
        submissions[id][author] = Submission(hash, uint64(block.timestamp));
        emit WorkSubmitted(id, author, msg.sender, hash, uri);
    }

    function _deposit(uint256 amount) private {
        uint256 beforeBalance = paymentToken.balanceOf(address(this));
        paymentToken.safeTransferFrom(msg.sender, address(this), amount);
        uint256 afterBalance = paymentToken.balanceOf(address(this));
        if (afterBalance < beforeBalance || afterBalance - beforeBalance != amount) revert UnsupportedTransfer();
    }

    function _credit(address account, uint256 amount) private {
        totalLocked -= amount;
        totalClaimable += amount;
        claimable[account] += amount;
    }

    function _refund(uint256 id, Bounty storage b, Status status) private {
        b.status = status;
        _credit(b.creator, b.reward);
        emit BountyRefunded(id, b.creator, b.reward, status);
    }
}
