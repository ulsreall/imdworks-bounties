// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/// @notice ERC-20 behavioural mocks used to model issuer restrictions against the
///         unmodified IMDWorksEscrow. Each mock is a distinct "issuer policy".
///         No live token or administrator is touched.

interface IEscrowTarget {
    function withdraw(address recipient) external;
    function award(uint256 id, address winner) external;
    function claimable(address account) external view returns (uint256);
    function totalLocked() external view returns (uint256);
}

/// 1. Standard, exact transfers, 6 decimals. Baseline supported asset.
contract StandardToken {
    string public constant symbol = "STD";
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 a) external { balanceOf[to] += a; }

    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a;
        return true;
    }

    function transfer(address to, uint256 a) public virtual returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }

    function transferFrom(address f, address to, uint256 a) public virtual returns (bool) {
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        balanceOf[f] -= a;
        balanceOf[to] += a;
        return true;
    }
}

/// 2. Issuer can pause all transfers (deposit and payout both blocked).
contract PausedToken is StandardToken {
    bool public paused;
    function setPaused(bool p) external { paused = p; }
    function transfer(address to, uint256 a) public override returns (bool) {
        require(!paused, "TOKEN_PAUSED");
        return super.transfer(to, a);
    }
    function transferFrom(address f, address to, uint256 a) public override returns (bool) {
        require(!paused, "TOKEN_PAUSED");
        return super.transferFrom(f, to, a);
    }
}

/// 3. Issuer blocks specific senders (e.g. sanctions list on the creator).
contract SenderRestrictedToken is StandardToken {
    mapping(address => bool) public blockedSender;
    function setBlockedSender(address a, bool v) external { blockedSender[a] = v; }
    function transfer(address to, uint256 a) public override returns (bool) {
        require(!blockedSender[msg.sender], "SENDER_BLOCKED");
        return super.transfer(to, a);
    }
    function transferFrom(address f, address to, uint256 a) public override returns (bool) {
        require(!blockedSender[f], "SENDER_BLOCKED");
        return super.transferFrom(f, to, a);
    }
}

/// 4. Issuer blocks specific recipients (e.g. a blocked winner address).
contract RecipientRestrictedToken is StandardToken {
    mapping(address => bool) public blockedRecipient;
    function setBlockedRecipient(address a, bool v) external { blockedRecipient[a] = v; }
    function transfer(address to, uint256 a) public override returns (bool) {
        require(!blockedRecipient[to], "RECIPIENT_BLOCKED");
        return super.transfer(to, a);
    }
}

/// 5. Returns false instead of reverting (ERC-20 spec violation).
contract ReturnFalseToken is StandardToken {
    bool public fail;
    function setFail(bool f) external { fail = f; }
    function transfer(address to, uint256 a) public override returns (bool) {
        if (fail) return false;
        return super.transfer(to, a);
    }
    function transferFrom(address f, address to, uint256 a) public override returns (bool) {
        if (fail) return false;
        return super.transferFrom(f, to, a);
    }
}

/// 6. No return value at all (older tokens). SafeERC20 must tolerate this.
contract NoReturnToken {
    string public constant symbol = "NRT";
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 a) external { balanceOf[to] += a; }

    function approve(address s, uint256 a) external {
        allowance[msg.sender][s] = a;
    }

    function transfer(address to, uint256 a) external {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
    }

    function transferFrom(address f, address to, uint256 a) external {
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        balanceOf[f] -= a;
        balanceOf[to] += a;
    }
}

/// 7. Transfer tax: recipient receives less than sent (fee-on-transfer).
contract FeeOnTransferToken is StandardToken {
    uint256 public feeBps = 100; // 1%
    mapping(address => uint256) public fees;
    function setFeeBps(uint256 b) external { feeBps = b; }
    function transfer(address to, uint256 a) public override returns (bool) {
        uint256 fee = (a * feeBps) / 10_000;
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a - fee;
        fees[address(this)] += fee;
        return true;
    }
    function transferFrom(address f, address to, uint256 a) public override returns (bool) {
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        uint256 fee = (a * feeBps) / 10_000;
        balanceOf[f] -= a;
        balanceOf[to] += a - fee;
        fees[address(this)] += fee;
        return true;
    }
}

/// 8. Callback token (ERC-777-style): re-enters the escrow during transfer hooks.
contract ReentrantToken is StandardToken {
    address public escrow;
    bool public attackEnabled;
    bool public outerTransferSucceeded;
    bytes public lastCallbackRevert;
    uint256 public callbackAttempts;

    function configure(address escrow_, bool enabled) external {
        escrow = escrow_;
        attackEnabled = enabled;
    }

    function _attack() internal {
        if (!attackEnabled || escrow == address(0)) return;
        callbackAttempts++;
        // 1st attempt: a fresh withdraw by the token contract (must revert: no credit)
        try IEscrowTarget(escrow).withdraw(address(0xBAD)) {
            outerTransferSucceeded = true;
        } catch (bytes memory reason) {
            lastCallbackRevert = reason;
        }
        // 2nd attempt: re-enter award() on a live bounty (must revert: no auth)
        try IEscrowTarget(escrow).award(1, address(this)) {
            outerTransferSucceeded = true;
        } catch (bytes memory reason) {
            lastCallbackRevert = reason;
        }
    }

    function transfer(address to, uint256 a) public override returns (bool) {
        _attack();
        return super.transfer(to, a);
    }

    function transferFrom(address f, address to, uint256 a) public override returns (bool) {
        _attack();
        return super.transferFrom(f, to, a);
    }
}
