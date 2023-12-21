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

# Protocol Summary

The ThunderLoan protocol is meant to do the following:

1. Give users a way to create flash loans
2. Give liquidity providers a way to earn money off their capital

Liquidity providers can `deposit` assets into `ThunderLoan` and be given `AssetTokens` in return. These `AssetTokens` gain interest over time depending on how often people take out flash loans!

We are planning to upgrade from the current `ThunderLoan` contract to the `ThunderLoanUpgraded` contract. Please include this upgrade in scope of a security review.

# Disclaimer

zxarcs makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by zxarcs is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

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
interfaces
  IFlashLoanReceiver.sol
  IPoolFactory.sol
  ITSwapPool.sol
  IThunderLoan.sol
protocol
  AssetToken.sol
  OracleUpgradeable.sol
  ThunderLoan.sol
  upgradedProtocol
  ThunderLoanUpgraded.sol
```
## Summary of Findings

* H01 - When using a proxy pattern and changing the implementation contract, existing storage variables in both contracts have to reside in same storage slots
* H02 - Updating exchange rate on token deposit will inflate asset token's exchange rate faster than expected
* M01 - Because only one liquidity pool is used to get asset token price, there exist opportunity for price manipulation through flash loans

## Tools Used

- Foundry
- Manual audit

# High

## When using a proxy pattern and changing the implementation contract, existing storage variables in both contracts have to reside in same storage slots

### Summary

State variables are not in the same storage memory slots.
After contract upgrade, both storage memory at index one and at index two will be overwritten with bad data.

### Details

In part, storage memory slots for the current `ThunderLoan.sol` contract looks like this:
```
slot n: token-to-asset-token mapping
slot n+1: fee precision
slot n+2: flash loan fee
// other state variables
```

In part, storage memory slots for the planned `ThunderLoanUpgraded.sol` contract looks like this:
```
slot n: token-to-asset-token mapping
slot n+1: flash loan fee // this will overwrite the fee precision above
// fee precision not a storage memory variable any more since it is marked as constant
slot n+2: is token currently flash loaning mapping
// other state variables
```

When the proxy contract uses `delegatecall` low level function, it will execute logic from  one of these implementation contracts and update the storage memory of the proxy contract itself.

This means that (before the upgrade) when flash loan fee is updated (at some point), the proxy's storage slot at that specific location will be updated.

After the upgrade, fee precision is changed to a constant meaning that it will **not** be part of the contract storage memory any more as it was in previous contract version. That storage slot will now instead be associated flash loan fee and (once first flash loan executes) flash loan fee with data related to `s_currentlyFlashLoaning` mapping which will be 0x0...0 since the initial storage slot for mappings is 0x0...0 (with mapping data stored elsewhere).

This can introduce many unexpected issues because wrong state variables are being updated.

### Filename

`src/upgradedProtocol/ThunderLoanUpgraded.sol`

### Permalinks

https://github.com/Cyfrin/2023-11-Thunder-Loan/blob/8539c83865eb0d6149e4d70f37a35d9e72ac7404/src/upgradedProtocol/ThunderLoanUpgraded.sol#L96-L97

### Impact

After protocol update to `ThunderLoanUpgraded.sol` contract, multiple state variables will be overwritten leading to many issues, know and unknown.

### Recommendations

Do not change fee precision to a `constant`. This will introduce many issues, as explained above.
In addition, do not change order of state variables in `ThunderLoanUpgraded.sol`.
Keep state variables in same storage memory slots in `ThunderLoanUpgraded.sol` as they are in `ThunderLoan.sol`

> Note: Additional changes will need to be made to `FEE_PRECISION`. Recommended to keep the same implementation with `s_feePrecision` as in previous version of the contract in `ThunderLoan.sol`.
```diff
+ uint256 private s_feePrecision;
+ uint256 private s_flashLoanFee; // 0.3% ETH fee
- uint256 private s_flashLoanFee; // 0.3% ETH fee
- uint256 public constant FEE_PRECISION = 1e18;
```

### POC

src/upgradedProtocol/ThunderLoanUpgraded.sol

Change is needed in ThunderLoanUpgraded.sol so that the initialize function can run. See H-4
```solidity
function initialize(address tswapAddress) external reinitializer(2) {
	__Ownable_init();
	__UUPSUpgradeable_init();
	__Oracle_init(tswapAddress);
	s_flashLoanFee = 3e15; // 0.3% ETH fee
}
```

test/unit/ThunderLoanTest.t.sol
```solidity
import { ThunderLoanUpgraded } from "src/upgradedProtocol/ThunderLoanUpgraded.sol";
//...

function testUpgradeSetsWrongFeePrecisionAndFee() public {
	uint256 feePrecisionBeforeUpgrade;
	uint256 feePrecisionAfterUpgrade;

	console.log("address(thunderLoan) slots");
	for (uint256 i = 0; i < 250; i++) {
		bytes32 slot = vm.load(address(proxy), bytes32(uint256(i)));
		//console.logBytes32(slot);
		uint256 slotUint = uint256(slot);

		if (i == 203) {
			feePrecisionBeforeUpgrade = slotUint;
		}

		if (slotUint > 0) {
			console.log("index %s value %s", i, slotUint);
		}
	}
	// output:
	//   index 0 value 1
	//   index 51 value 728815563385977040452943777879061427756277306518
	//   index 201 value 263400868551549723330807389252719309078400616203
	//   index 203 value 1000000000000000000 <- s_feePrecision

	// deploy the new version and upgrade proxy
	ThunderLoanUpgraded thunderLoanV2Implementation = new ThunderLoanUpgraded();
	thunderLoan.upgradeToAndCall(
		address(thunderLoanV2Implementation), abi.encodeWithSignature("initialize(address)", address(mockPoolFactory))
	);

	console.log("address(thunderLoanV2Implementation) slots");
	for (uint256 i = 0; i < 250; i++) {
		bytes32 slot = vm.load(address(proxy), bytes32(uint256(i)));
		//console.logBytes32(slot);
		uint256 slotUint = uint256(slot);

		if (i == 203) {
			feePrecisionAfterUpgrade = slotUint;
		}

		if (slotUint > 0) {
			console.log("index %s value %s", i, slotUint);
		}
	}
	// output:
	//   index 0 value 1
	//   index 51 value 728815563385977040452943777879061427756277306518
	//   index 201 value 917977473271046311748067258655037622845262362008
	//   index 203 value 3000000000000000 <- s_feePrecision (overwritten by s_flashLoanFee)

	assertNotEq(feePrecisionBeforeUpgrade, feePrecisionAfterUpgrade);
}

```
> Note: Not clear if when this POC is ran, storage variables will be at exact same index like they were for me. The point will still stand though because which ever storage index they are in the fee precision will be overwritten when the update happens.

## Updating exchange rate on token deposit will inflate asset token's exchange rate faster than expected
### Summary

Exchange rate for asset token is updated on deposit. This means users can deposit (which will increase exchange rate), and then immediately withdraw more underlying tokens than they deposited. 

### Details

Per documentation:
> Liquidity providers can deposit assets into ThunderLoan and be given AssetTokens in return. **These AssetTokens gain interest over time depending on how often people take out flash loans!**

Asset tokens gain interest when people take out flash loans with the underlying tokens. In current version of ThunderLoan, exchange rate is also updated when user deposits underlying tokens.

This does not match with documentation and will end up causing exchange rate to increase on deposit.

This will allow anyone who deposits to immediately withdraw and get more tokens back than they deposited. Underlying of any asset token can be completely drained in this manner.

### Filename

`src/protocol/ThunderLoan.sol`

### Permalinks

https://github.com/Cyfrin/2023-11-Thunder-Loan/blob/8539c83865eb0d6149e4d70f37a35d9e72ac7404/src/protocol/ThunderLoan.sol#L153-L154

### Impact

Users can deposit and immediately withdraw more funds. Since exchange rate is increased on deposit, they will withdraw more funds then they deposited without any flash loans being taken at all.

### Recommendations

It is recommended to not update exchange rate on deposits and updated it only when flash loans are taken, as per documentation.
```diff
function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
	AssetToken assetToken = s_tokenToAssetToken[token];
	uint256 exchangeRate = assetToken.getExchangeRate();
	uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
	emit Deposit(msg.sender, token, amount);
	assetToken.mint(msg.sender, mintAmount);
-	uint256 calculatedFee = getCalculatedFee(token, amount);
-	assetToken.updateExchangeRate(calculatedFee);
	token.safeTransferFrom(msg.sender, address(assetToken), amount);
}
```

### POC

```solidity
function testExchangeRateUpdatedOnDeposit() public setAllowedToken {
	tokenA.mint(liquidityProvider, AMOUNT);
	tokenA.mint(user, AMOUNT);

	// deposit some tokenA into ThunderLoan
	vm.startPrank(liquidityProvider);
	tokenA.approve(address(thunderLoan), AMOUNT);
	thunderLoan.deposit(tokenA, AMOUNT);
	vm.stopPrank();

	// another user also makes a deposit
	vm.startPrank(user);
	tokenA.approve(address(thunderLoan), AMOUNT);
	thunderLoan.deposit(tokenA, AMOUNT);
	vm.stopPrank();        

	AssetToken assetToken = thunderLoan.getAssetFromToken(tokenA);

	// after a deposit, asset token's exchange rate has aleady increased
	// this is only supposed to happen when users take flash loans with underlying
	assertGt(assetToken.getExchangeRate(), 1 * assetToken.EXCHANGE_RATE_PRECISION());

	// now liquidityProvider withdraws and gets more back because exchange
	// rate is increased but no flash loans were taken out yet
	// repeatedly doing this could drain all underlying for any asset token
	vm.startPrank(liquidityProvider);
	thunderLoan.redeem(tokenA, assetToken.balanceOf(liquidityProvider));
	vm.stopPrank();

	assertGt(tokenA.balanceOf(liquidityProvider), AMOUNT);
}
```

# Medium

## Because only one liquidity pool is used to get asset token price, there exist opportunity for price manipulation through flash loans

### Summary

A single liquidity pool should never be used as sole source of price market data. These liquidity pool can be flash loan funded and therefore token price can be skewed drastically which can be used in many DeFi attacks.

### Details

An attacker can use a flash loan to manipulate a price of a token on a DEX. Once the price is temporarily manipulated with the flash loan funds, the attacker can then go to a protocol (that relies solely on the DEX pool for price info) and use manipulated funds to buy or sell assets at above or below market price.

Centralized, single source price oracles (e.g. a single Uniswap liquidity pool) should never be used.

### Filename

`src/protocol/OracleUpgradeable.sol`

### Permalinks

https://github.com/Cyfrin/2023-11-Thunder-Loan/blob/8539c83865eb0d6149e4d70f37a35d9e72ac7404/src/protocol/OracleUpgradeable.sol#L21C36-L21C36

### Impact

Price of a token in a DEX can be manipulated via a flash loan and then any lending protocols that depend on that DEX pool for price info will be at risk of an attack.

### Recommendations

Use a decentralized price oracle such as Chainlink.

