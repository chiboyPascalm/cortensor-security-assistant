// Example contract for testing the scanner.
pragma solidity ^0.8.20;

contract ExampleWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function unsafeCheck() public view returns (bool) {
        return tx.origin == owner;
    }

    function execute(address target, bytes calldata data) public {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }
}
