# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Severity Criteria](#severity-criteria)
  - [Summary of Findings](#summary-of-findings)
  - [Tools Used](#tools-used)
- [High](#high)

# Protocol Summary
A smart contract application for storing a password. Users should be able to store a password and then retrieve it later. Others should not be able to access the password.

# Disclaimer
Zxarcs makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by zxarcs is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification
|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 

## Scope
```
./src/
└── PasswordStore.sol
```

## Severity Criteria

## Summary of Findings
* Access control is needed in the `setPassword` function. Otherwise, anyone can change the password.
* All on-chain data is public and visible to anyone. Critical data (e.g. passwords) should not be stored on-chain.

# High

## (H-1) Not having any access control on setPassword function allows anyone to set the password

### Summary
Access control is needed in the `setPassword` function. Otherwise, anyone can change the password.

### Details
If there is no access control in the `setPassword` function anyone can set the password to anything they want and then use the password to access protected data or access parts of the code where the password is required.

A check should be added so that only owner can update the password, just like how it is done in `getPassword` function.

### Filename
`src/PasswordStore.sol`

### Permalinks
https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L26

### Tools Used
* Foundry
* Manual audit

### Impact

### Recommendations
```diff
-    function setPassword(string memory newPassword) external {
+    function setPassword(string memory newPassword) external {
+       if (msg.sender != s_owner) {
+           revert PasswordStore__NotOwner();
+       }
```

### POC
```solidity
function test_non_owner_can_set_password() public {
	//non-owner successfully calls setPassword function
	vm.prank(address(1));
	string memory newPwd = "Mynewpassword123";
	passwordStore.setPassword(newPwd);
	
	//retrieve password with owner address to verify
	//that it in fact changed to what the non-owner set
	vm.prank(owner);
	string memory actualPassword = passwordStore.getPassword();
	assertEq(actualPassword, newPwd);
}
```
## (H-2) Since all on-chain data is public, anyone can see what the current password is

### Summary
All on-chain data is public and visible to anyone. Critical data (e.g. passwords) should not be stored on-chain.

### Details
`s_password` state variable is marked as `private` but this does not prevent anyone from seeing what its value is because all on-chain data is public and visible to anyone.

### Filename
`src/PasswordStore.sol`

### Permalinks
https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L14C31-L14C31

### Impact
Anyone can see the current password.

### Recommendations
Passwords and other critical data should never be saved on-chain. This is not a good use case for blockchain since all data is publicly visible. Recommendation is to store passwords in a different manner, such as a password manager software.

### POC
```solidity
function test_non_owner_can_view_password() public {
	// owner sets a new password
	string memory newPassword = "1Nice#pwd";
	bytes32 newPasswordBytes32 = bytes32(abi.encodePacked(newPassword));
	vm.prank(address(owner));
	passwordStore.setPassword(newPassword);

	// non-owner can see what the new password is
	vm.prank(address(1));
	bytes32 data = vm.load(address(passwordStore), bytes32(uint256(1)));
	// strings shorter than 31 bytes include string length data,
	// remove it so it doesn't interfere when we cast to string to see
	// the password, otherwise the password could have extra characters
	// and therefore be wrong.

	// this simple example is not setup to handle passwords with 32 characters
	// or greater because they are stored differently in the contract's
	// storage slots.
	bytes31 cutData = bytes31(abi.encodePacked(data));
	bytes32 dataWithoutLength = bytes32(abi.encodePacked(cutData, new bytes(1)));
	console.log(string(abi.encodePacked(dataWithoutLength))); // password from storage slot
	assertEq(newPasswordBytes32, dataWithoutLength);
	assertEq(string(abi.encodePacked(newPasswordBytes32)), string(abi.encodePacked(dataWithoutLength)));
}
```
