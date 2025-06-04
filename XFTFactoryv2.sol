// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title XFTFactory
 * @dev Factory for deterministic deployment using CREATE2 with tracking
 * and a seamless deployment process
 */
contract XFTFactory is AccessControl {
    // ======== ROLES ========
    bytes32 public constant DEPLOYER_ROLE = keccak256("DEPLOYER_ROLE");
    
    // ======== STRUCTS ========
    struct DeploymentInfo {
        address deployer;
        uint256 timestamp;
        bytes32 presetId;
        bytes32 bytecodeHash;
        string metadata;
    }
    
    struct DeploymentConfig {
        bytes32 presetId;
        bytes constructorArgs;
        string metadata;
    }
    
    // ======== EVENTS ========
    event Deployed(address indexed deployedAddress, uint256 indexed salt, bytes32 bytecodeHash, string metadata);
    event PresetRegistered(bytes32 indexed presetId, string name);
    event PresetUpdated(bytes32 indexed presetId, string name);
    event ProxyDeployed(address indexed proxy, address indexed implementation, string metadata);
    event BatchDeployed(address[] deployedAddresses, uint256 saltBase);
    
    // ======== STATE VARIABLES ========
    mapping(bytes32 => bool) public saltBytecodeUsed;
    mapping(address => DeploymentInfo) public deploymentInfo;
    mapping(bytes32 => bytes) public presets;
    mapping(bytes32 => string) public presetNames;
    mapping(address => uint256) public userSaltNonce;
    
    // ======== CONSTRUCTOR ========
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DEPLOYER_ROLE, msg.sender);
    }
    
    // ======== PRESET MANAGEMENT ========
    /**
     * @dev Registers a new contract preset
     * @param name Name of the preset for reference
     * @param bytecode Contract bytecode
     * @return presetId The ID used to reference this preset
     */
    function registerPreset(string calldata name, bytes calldata bytecode) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        returns (bytes32 presetId) 
    {
        require(bytes(name).length > 0, "XFTFactory: preset name cannot be empty");
        require(bytecode.length > 0, "XFTFactory: bytecode cannot be empty");
        
        presetId = keccak256(abi.encode(name));
        presets[presetId] = bytecode;
        presetNames[presetId] = name;
        
        emit PresetRegistered(presetId, name);
        return presetId;
    }
    
    /**
     * @dev Updates an existing preset
     * @param presetId ID of the preset to update
     * @param bytecode New contract bytecode
     */
    function updatePreset(bytes32 presetId, bytes calldata bytecode) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        require(presets[presetId].length > 0, "XFTFactory: preset does not exist");
        require(bytecode.length > 0, "XFTFactory: bytecode cannot be empty");
        
        presets[presetId] = bytecode;
        
        emit PresetUpdated(presetId, presetNames[presetId]);
    }
    
    // ======== DEPLOYMENT FUNCTIONS ========
    /**
     * @dev Deploy a contract using a registered preset
     * @param presetId The ID of the preset to deploy
     * @param constructorArgs Constructor arguments for the contract
     * @param metadata Additional deployment metadata for tracking
     * @return The address of the deployed contract
     */
    function deployPreset(
        bytes32 presetId,
        bytes calldata constructorArgs,
        string calldata metadata
    ) 
        external 
        onlyRole(DEPLOYER_ROLE) 
        returns (address) 
    {
        bytes memory bytecode = presets[presetId];
        require(bytecode.length > 0, "XFTFactory: preset not found");
        
        uint256 salt = _generateSalt(presetId, constructorArgs);
        return _deployWithTracking(salt, bytecode, constructorArgs, presetId, metadata);
    }
    
    /**
     * @dev Deploy a contract with custom bytecode
     * @param bytecode Contract bytecode
     * @param constructorArgs Constructor arguments for the contract
     * @param metadata Additional deployment metadata for tracking
     * @return The address of the deployed contract
     */
    function deploy(
        bytes calldata bytecode,
        bytes calldata constructorArgs,
        string calldata metadata
    ) 
        external 
        onlyRole(DEPLOYER_ROLE) 
        returns (address) 
    {
        require(bytecode.length > 0, "XFTFactory: invalid bytecode");
        
        uint256 salt = _generateSalt(keccak256(bytecode), constructorArgs);
        return _deployWithTracking(salt, bytecode, constructorArgs, bytes32(0), metadata);
    }
    
    /**
     * @dev Deploy a contract with a specific salt
     * @param salt Deterministic salt for deployment
     * @param bytecode Contract bytecode
     * @param constructorArgs Constructor arguments for the contract
     * @param metadata Additional deployment metadata for tracking
     * @return The address of the deployed contract
     */
    function deployWithSalt(
        uint256 salt,
        bytes calldata bytecode,
        bytes calldata constructorArgs,
        string calldata metadata
    ) 
        external 
        onlyRole(DEPLOYER_ROLE) 
        returns (address) 
    {
        require(bytecode.length > 0, "XFTFactory: invalid bytecode");
        return _deployWithTracking(salt, bytecode, constructorArgs, bytes32(0), metadata);
    }
    
    /**
     * @dev Deploy a proxy pointing to an implementation contract with initialization
     * @param implementation Address of the implementation contract
     * @param initData Initialization data to be called on the proxy
     * @param metadata Additional deployment metadata for tracking
     * @return The address of the deployed proxy
     */
    function deployProxy(
        address implementation,
        bytes calldata initData,
        string calldata metadata
    ) 
        external 
        onlyRole(DEPLOYER_ROLE) 
        returns (address) 
    {
        require(implementation != address(0), "XFTFactory: invalid implementation");
        
        bytes memory proxyCode = abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            implementation,
            hex"5af43d82803e903d91602b57fd5bf3"
        );
        
        uint256 salt = _generateSalt(bytes32(uint256(uint160(implementation))), initData);
        address proxy = _deploy(salt, proxyCode);
        
        deploymentInfo[proxy] = DeploymentInfo({
            deployer: msg.sender,
            timestamp: block.timestamp,
            presetId: bytes32(uint256(uint160(implementation))),
            bytecodeHash: keccak256(proxyCode),
            metadata: metadata
        });
        
        if(initData.length > 0) {
            (bool success, ) = proxy.call(initData);
            require(success, "XFTFactory: proxy initialization failed");
        }
        
        emit ProxyDeployed(proxy, implementation, metadata);
        return proxy;
    }
    
    /**
     * @dev Deploy multiple contracts in a batch using presets
     * @param configs Array of deployment configurations
     * @return deployedAddresses Array of deployed contract addresses
     */
    function batchDeployPresets(
        DeploymentConfig[] calldata configs
    ) 
        external 
        onlyRole(DEPLOYER_ROLE) 
        returns (address[] memory deployedAddresses) 
    {
        require(configs.length > 0, "XFTFactory: empty configs array");
        
        deployedAddresses = new address[](configs.length);
        
        for (uint256 i = 0; i < configs.length; i++) {
            bytes memory bytecode = presets[configs[i].presetId];
            require(bytecode.length > 0, "XFTFactory: preset not found");
            
            uint256 salt = _generateSalt(configs[i].presetId, configs[i].constructorArgs);
            salt = uint256(keccak256(abi.encodePacked(salt, i))); // Add index to ensure uniqueness
            
            deployedAddresses[i] = _deployWithTracking(
                salt,
                bytecode,
                configs[i].constructorArgs,
                configs[i].presetId,
                configs[i].metadata
            );
        }
        
        emit BatchDeployed(deployedAddresses, block.timestamp);
        return deployedAddresses;
    }
    
    // ======== INTERNAL FUNCTIONS ========
    /**
     * @dev Deploy a contract and track its deployment info
     */
    function _deployWithTracking(
        uint256 salt,
        bytes memory bytecode,
        bytes memory constructorArgs,
        bytes32 presetId,
        string memory metadata
    ) internal returns (address) {
        bytes memory fullBytecode = constructorArgs.length > 0 ? 
            abi.encodePacked(bytecode, constructorArgs) : bytecode;
        
        address deployed = _deploy(salt, fullBytecode);
        
        deploymentInfo[deployed] = DeploymentInfo({
            deployer: msg.sender,
            timestamp: block.timestamp,
            presetId: presetId,
            bytecodeHash: keccak256(fullBytecode),
            metadata: metadata
        });
        
        emit Deployed(deployed, salt, keccak256(fullBytecode), metadata);
        return deployed;
    }
    
    /**
     * @dev Core deployment function using CREATE2
     */
    function _deploy(uint256 salt, bytes memory bytecode) internal returns (address deployed) {
        bytes32 saltBytecodeHash = keccak256(abi.encodePacked(salt, keccak256(bytecode)));
        require(!saltBytecodeUsed[saltBytecodeHash], "XFTFactory: salt already used for this bytecode");
        saltBytecodeUsed[saltBytecodeHash] = true;
        
        assembly {
            deployed := create2(0, add(bytecode, 32), mload(bytecode), salt)
            if iszero(deployed) {
                mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(4, 32)
                mstore(36, 21)
                mstore(68, "Deployment failed")
                revert(0, 100)
            }
        }
        
        return deployed;
    }
    
    /**
     * @dev Generate a deterministic salt based on preset, args and user nonce
     */
    function _generateSalt(bytes32 presetId, bytes memory constructorArgs) internal returns (uint256) {
        return uint256(keccak256(abi.encode(
            block.chainid,
            msg.sender,
            userSaltNonce[msg.sender]++,
            presetId,
            keccak256(constructorArgs)
        )));
    }
    
    // ======== VIEW FUNCTIONS ========
    /**
     * @dev Predict address for a preset deployment
     */
    function predictPresetAddress(
        bytes32 presetId,
        bytes calldata constructorArgs
    ) external view returns (address) {
        bytes memory bytecode = presets[presetId];
        require(bytecode.length > 0, "XFTFactory: preset not found");
        
        uint256 salt = uint256(keccak256(abi.encode(
            block.chainid,
            msg.sender,
            userSaltNonce[msg.sender],
            presetId,
            keccak256(constructorArgs)
        )));
        
        bytes memory fullBytecode = constructorArgs.length > 0 ? 
            abi.encodePacked(bytecode, constructorArgs) : bytecode;
            
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(fullBytecode)
        )))));
    }
    
    /**
     * @dev Predict address for a custom bytecode deployment
     */
    function predictAddress(
        bytes calldata bytecode,
        bytes calldata constructorArgs
    ) external view returns (address) {
        uint256 salt = uint256(keccak256(abi.encode(
            block.chainid,
            msg.sender,
            userSaltNonce[msg.sender],
            keccak256(bytecode),
            keccak256(constructorArgs)
        )));
        
        bytes memory fullBytecode = constructorArgs.length > 0 ? 
            abi.encodePacked(bytecode, constructorArgs) : bytecode;
            
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(fullBytecode)
        )))));
    }
    
    /**
     * @dev Get preset information by ID
     */
    function getPresetInfo(bytes32 presetId) external view returns (string memory name, bool exists) {
        name = presetNames[presetId];
        exists = presets[presetId].length > 0;
    }
    
    /**
     * @dev Verify if an address was deployed through this factory
     */
    function isDeployed(address target) external view returns (bool) {
        return deploymentInfo[target].timestamp > 0;
    }
    
    /**
     * @dev Check if a salt has been used for specific bytecode
     */
    function isSaltUsed(uint256 salt, bytes calldata bytecode) external view returns (bool) {
        bytes32 saltBytecodeHash = keccak256(abi.encodePacked(salt, keccak256(bytecode)));
        return saltBytecodeUsed[saltBytecodeHash];
    }
    
    /**
     * @dev Get all deployment information for a contract
     */
    function getDeploymentDetails(address deployment) 
        external 
        view 
        returns (
            address deployer,
            uint256 timestamp,
            string memory presetName,
            bytes32 bytecodeHash,
            string memory metadata
        ) 
    {
        DeploymentInfo memory info = deploymentInfo[deployment];
        require(info.timestamp > 0, "XFTFactory: contract not deployed through this factory");
        
        return (
            info.deployer,
            info.timestamp,
            presetNames[info.presetId],
            info.bytecodeHash,
            info.metadata
        );
    }
}
