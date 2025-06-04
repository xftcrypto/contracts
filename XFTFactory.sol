// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title XFTFactory
 * @dev Deterministic deployment using CREATE2 with access control, gas optimizations, and batch functionality
 */
contract XFTFactory {
    // ======== EVENTS ========
    event Deployed(address indexed deployedAddress, uint256 indexed salt, bytes32 bytecodeHash);
    event DeployedWithParams(address indexed deployedAddress, uint256 indexed salt, bytes32 bytecodeHash, bytes params);
    event BatchDeployed(address[] deployedAddresses, uint256 indexed saltBase);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    // ======== STATE VARIABLES ========
    address public owner;
    mapping(bytes32 => bool) public saltBytecodeUsed; // Tracks salt+bytecode combinations
    mapping(address => bool) public isDeployed;
    
    // ======== MODIFIERS ========
    modifier onlyOwner() {
        require(msg.sender == owner, "XFTFactory: caller is not the owner");
        _;
    }

    // ======== CONSTRUCTOR ========
    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }
    
    // ======== OWNER FUNCTIONS ========
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "XFTFactory: new owner is the zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
    
    // ======== DEPLOYMENT FUNCTIONS ========
    function deploy(uint256 salt, bytes calldata bytecode) external onlyOwner returns (address deployedAddress) {
        require(bytecode.length > 0, "XFTFactory: invalid bytecode");
        bytes32 saltBytecodeHash = keccak256(abi.encodePacked(salt, keccak256(bytecode)));
        require(!saltBytecodeUsed[saltBytecodeHash], "XFTFactory: salt already used for this bytecode");
        saltBytecodeUsed[saltBytecodeHash] = true;
        
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, add(bytecode.offset, 32), bytecode.length)
            mstore(0x40, add(ptr, add(bytecode.length, 32)))
            deployedAddress := create2(0, ptr, bytecode.length, salt)
            if iszero(deployedAddress) {
                mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(4, 32)
                mstore(36, 21)
                mstore(68, "Deployment failed")
                revert(0, 100)
            }
        }
        
        isDeployed[deployedAddress] = true;
        emit Deployed(deployedAddress, salt, keccak256(bytecode));
        return deployedAddress;
    }
    
    function deployWithParams(
        uint256 salt,
        bytes calldata bytecode,
        bytes calldata constructorArgs
    ) external onlyOwner returns (address deployedAddress) {
        require(bytecode.length > 0, "XFTFactory: invalid bytecode");
        bytes32 saltBytecodeHash = keccak256(abi.encodePacked(salt, keccak256(abi.encodePacked(bytecode, constructorArgs))));
        require(!saltBytecodeUsed[saltBytecodeHash], "XFTFactory: salt already used for this bytecode+args");
        saltBytecodeUsed[saltBytecodeHash] = true;
        
        bytes memory fullBytecode = abi.encodePacked(bytecode, constructorArgs);
        
        assembly {
            let ptr := add(fullBytecode, 32)
            deployedAddress := create2(0, ptr, mload(fullBytecode), salt)
            if iszero(deployedAddress) {
                mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(4, 32)
                mstore(36, 21)
                mstore(68, "Deployment failed")
                revert(0, 100)
            }
        }
        
        isDeployed[deployedAddress] = true;
        emit DeployedWithParams(deployedAddress, salt, keccak256(fullBytecode), constructorArgs);
        return deployedAddress;
    }
    
    function batchDeploy(
        uint256 saltBase,
        bytes[] calldata bytecodes
    ) external onlyOwner returns (address[] memory deployedAddresses) {
        require(bytecodes.length > 0, "XFTFactory: empty bytecodes array");
        deployedAddresses = new address[](bytecodes.length);
        
        for (uint256 i = 0; i < bytecodes.length; i++) {
            require(bytecodes[i].length > 0, "XFTFactory: invalid bytecode");
            uint256 salt = uint256(keccak256(abi.encodePacked(saltBase, i)));
            bytes32 saltBytecodeHash = keccak256(abi.encodePacked(salt, keccak256(bytecodes[i])));
            require(!saltBytecodeUsed[saltBytecodeHash], "XFTFactory: salt already used for this bytecode");
            saltBytecodeUsed[saltBytecodeHash] = true;
            
            address deployedAddress;
            assembly {
                let ptr := mload(0x40)
                let bytecodeOffset := add(bytecodes.offset, mul(i, 0x20))
                bytecodeOffset := add(bytecodeOffset, calldataload(bytecodeOffset))
                let bytecodeLength := calldataload(bytecodeOffset)
                calldatacopy(ptr, add(bytecodeOffset, 0x20), bytecodeLength)
                mstore(0x40, add(ptr, add(bytecodeLength, 32)))
                deployedAddress := create2(0, ptr, bytecodeLength, salt)
                if iszero(deployedAddress) {
                    mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(4, 32)
                    mstore(36, 32)
                    mstore(68, "Batch deployment failed at index")
                    mstore(100, i)
                    revert(0, 132)
                }
            }
            
            isDeployed[deployedAddress] = true;
            deployedAddresses[i] = deployedAddress;
            emit Deployed(deployedAddress, salt, keccak256(bytecodes[i]));
        }
        
        emit BatchDeployed(deployedAddresses, saltBase);
        return deployedAddresses;
    }
    
    function deployProxies(
        uint256 saltBase,
        uint256 count,
        address implementation
    ) external onlyOwner returns (address[] memory deployedAddresses) {
        require(implementation != address(0), "XFTFactory: invalid implementation");
        require(count > 0, "XFTFactory: count must be greater than zero");
        
        bytes memory proxyCode = abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            implementation,
            hex"5af43d82803e903d91602b57fd5bf3"
        );
        
        deployedAddresses = new address[](count);
        
        for (uint256 i = 0; i < count; i++) {
            uint256 salt = uint256(keccak256(abi.encodePacked(saltBase, i)));
            bytes32 saltBytecodeHash = keccak256(abi.encodePacked(salt, keccak256(proxyCode)));
            require(!saltBytecodeUsed[saltBytecodeHash], "XFTFactory: salt already used for this proxy");
            saltBytecodeUsed[saltBytecodeHash] = true;
            
            address deployedAddress;
            assembly {
                let ptr := mload(0x40)
                let bytecodeLength := mload(proxyCode)
                let bytecodePtr := add(proxyCode, 32)
                deployedAddress := create2(0, bytecodePtr, bytecodeLength, salt)
                if iszero(deployedAddress) {
                    mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(4, 32)
                    mstore(36, 27)
                    mstore(68, "Proxy deployment failed")
                    revert(0, 100)
                }
            }
            
            isDeployed[deployedAddress] = true;
            deployedAddresses[i] = deployedAddress;
            emit Deployed(deployedAddress, salt, keccak256(proxyCode));
        }
        
        emit BatchDeployed(deployedAddresses, saltBase);
        return deployedAddresses;
    }
    
    // ======== VIEW FUNCTIONS ========
    function predictAddress(uint256 salt, bytes calldata bytecode) external view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(bytecode)
        )))));
    }
    
    function predictBatchAddresses(
        uint256 saltBase, 
        bytes[] calldata bytecodes
    ) external view returns (address[] memory) {
        address[] memory addresses = new address[](bytecodes.length);
        for (uint256 i = 0; i < bytecodes.length; i++) {
            uint256 salt = uint256(keccak256(abi.encodePacked(saltBase, i)));
            addresses[i] = address(uint160(uint256(keccak256(abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecodes[i])
            )))));
        }
        return addresses;
    }
    
    function verifyDeployment(address deployedAddress) external view returns (bool) {
        return isDeployed[deployedAddress];
    }
    
    function isSaltUsed(uint256 salt, bytes calldata bytecode) external view returns (bool) {
        bytes32 saltBytecodeHash = keccak256(abi.encodePacked(salt, keccak256(bytecode)));
        return saltBytecodeUsed[saltBytecodeHash];
    }
}
