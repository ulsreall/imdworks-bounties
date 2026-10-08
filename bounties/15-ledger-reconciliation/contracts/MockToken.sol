// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/// @notice Exact-transfer ERC-20 used by the local reconciliation fixture.
///         Supports issuer pause so that a *failed withdrawal* is reproducible.
contract MockToken {
    string public constant name = "Fixtures USDG";
    string public constant symbol = "fUSDG";
    uint8 public constant decimals = 6;

    bool public paused;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event PausedSet(bool paused);

    function setPaused(bool value) external {
        paused = value;
        emit PausedSet(value);
    }

    function mint(address to, uint256 amount) external returns (bool) {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!paused, "TOKEN_PAUSED");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(!paused, "TOKEN_PAUSED");
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
