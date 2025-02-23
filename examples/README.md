> [!WARNING]
> The code has been made vulnerable on purpose. Please do not deploy or reuse this codebase in a live environment.

---

# Basic solidity security examples!

Here you have multiple small examples of basic security issue of solidity smart contracts to start your security journey. 


:star: `101`

- Logic bug
- Basic reentrancy 
	- [Short description at SWC-107](https://swcregistry.io/docs/SWC-107)
- Unencrypted secret data on-chain 
	- [Short description at SWC-136](https://swcregistry.io/docs/SWC-136)
- Weak pseudo-randomness 
	- [Short description at SWC-120](https://swcregistry.io/docs/SWC-120)
- Arithmetic overflow 
	- [Short description at SWC-101](https://swcregistry.io/docs/SWC-101)
- Access controls (both missing and through `tx.origin`) 
	- [Short description at SWC-115](https://swcregistry.io/docs/SWC-115)
- Force feeding ether 
	- [Short description at SWC-132](https://swcregistry.io/docs/SWC-132)
- Gas exhaustion 
	- [Short description at SWC-128](https://swcregistry.io/docs/SWC-128)


:star: `102`

- Push vs Pull approach (PoC can be found in test/)  
	- [Short description at SWC-113](https://swcregistry.io/docs/SWC-113)
- Cross-function reentrancy (PoC can be found in test/)
- Commit and reveal scheme implementations (PoC can be found in test/)
	- Pre-computable 
	- Replayable (+ frontrun)


## Next steps

The current version is `v0.2`. At the moment I would like to achieve the below in order to upgrade it:

:pushpin:`V1.0`

- Unchecked return value example https://swcregistry.io/docs/SWC-104
- Multiple examples per basic issue
- Foundry tests of the 101 issues
- Deploy to testnet and add etherscan links
- Additional reentrancy options: cross contract and token based

## My Understanding

### 101

**2-reentrancy**

If you want to deploy a contract, you must follow the principles of check, effect, and interaction. Otherwise, the attacker may use `receive()` function to cause a reentrancy attack.

```solidity
receive() external payable {
		if (address(target).balance >= 1 ether) {
			target.withdraw();
		}
}
```



**4-weak Randomness**

We cannot use block-related data to provide randomness, such as keccak256(abi.encodePacked(blockhash(block.number - 1)`. We also cannot trust the block timestamp because the miner could manipulate this data.



**6-access control**

When writing a contract, you must ensure that each function has appropriate access control.



**7-force feeding**

Solidity supports force-feeding ETH to contract. How to? For example:

```solidity
// 假设这是攻击者的操作步骤
// 1. 部署 Attacker 合约
let attacker = await Attacker.deploy()

// 2. 调用 forceFeedEth 函数，并发送 1 ETH
await attacker.forceFeedEth(example7Address, { 
    value: ethers.utils.parseEther("1.0") // 这就是 msg.value
})

contract Attacker {
    function forceFeedEth(address payable target) external payable {
        require(msg.value != 0, "No value sent!");  // 确保发送了 ETH
        selfdestruct(target);  // target 就是 Example7 合约的地址
    }
}
```

So if your contract has a function that needs to record the total deposit of ETH, it would be very vulnerable. Like this:

```solidity
assert(totalDeposit == address(this).balance); 	// Strict comparison of balance is vulnerable to force feeding Eth 
totalDeposit -= balance[msg.sender];
```



**8-gas exhaustion**

Never write code that uses an endless loop, or the loop may execute too many times. Otherwise, this could lead to gas exhaustion.



**9-unchecked call**

Sometimes the fail won't cause the contract to rollback. We need to check by ourselves at each key point. For example:

```solidity
function mint() external payable {
      // Requires 10 UMA tokens to mint an NFT
  uma_tkn.transferFrom(msg.sender, address(this), 10);

      uint256 tokenId = _nextTokenId++;		
  _safeMint(msg.sender, tokenId);
}
```

The transferFrom may fail to execute, but the contract will continue to run. We need to fix it by using:

```solidity
function mint() external payable {
    // 检查返回值
    bool success = uma_tkn.transferFrom(msg.sender, address(this), 10);
    require(success, "Token transfer failed");

    uint256 tokenId = _nextTokenId++;        
    _safeMint(msg.sender, tokenId);
}
```

Or use: `uma_tkn.safeTransferFrom(msg.sender, address(this), 10);`



### 102

**1-push pop**

如果发送 ETH 时带有函数调用数据，会调用 fallback()

如果发送纯 ETH（没有数据），会调用 receive()

.call{value: 40 ether}("") 发送了纯 ETH（空字符串 ""表示没有数据）

所以触发了 receive() 函数

```solidity
receive() external payable onlyOwner {
        require(msg.value > 0, "Zero transfer not allowed");
        require(msg.value % BATCH == 0, "You should add at least 1 ETH per participant");

        pot += msg.value;
}
```

由于有 onlyOwner 修饰符，只有合约 owner 才能成功发送 ETH

现在合约的问题在于所有参与人员想要取钱的时候

```solidity
  vm.prank(alice);
  target.participate();
  vm.prank(bob);
  target.participate();
  vm.prank(carol);
  target.participate();
  attacker.joinContest();
```

之前所有的参与人员都是一个普通地址，函数执行有receive也无所谓

```solidity
function retrieveAllPush() external participationClosed {
    for (uint256 i; i < winners.length; i++) {
        if (!winners[i].claimed) {
            winners[i].claimed = true;

            (bool success, ) = payable(winners[i].participant).call{value: pot / BATCH}("");
            require(success, "Transfer failed.");   
        }
    }
}
```

但是攻击者是一个合约，它自己有一个receive方法拒绝一切请求

```solidity
receive() external payable {
    revert("Next time you should use Pull over Push!");
}
```

这讲导致最后的交易行为作废，而前面成功的也会因为回滚而全部作废。所以`retrieveAllPush`设计是不安全的。这个函数不安全的地方就在于它尝试一次性给所有人都发钱。一旦有一个失败，那么所有的都失败。更好的方式是谁要领钱谁自己调用函数。比如写成这样：

```solidity
function retrieveOnePull() external participationClosed {
    for (uint256 i; i < winners.length; i++) { // An arbitrarily long list could be a problem, but this one is capped to BATCH
        if (winners[i].participant == msg.sender) {
            if (winners[i].claimed) revert("Already claimed!");
            winners[i].claimed = true;

            (bool success, ) = payable(msg.sender).call{value: pot / BATCH}("");
            require(success, "Transfer failed.");
        }
    }                  
}
```

细微的差别在于比较了msg.sender。最后可以写成这样，互不影响：

```solidity
vm.prank(bob);
target.retrieveOnePull();
assertEq(bob.balance, 10 ether, "Pull failed");

vm.prank(carol);
target.retrieveOnePull();
assertEq(carol.balance, 10 ether, "Pull failed");
```



**关于ERC20和ETH**

对于ERC20和ETH，他们之间交易是不同的，

```solidity
// ERC20 转账
token.transfer(recipient, amount);  // 这是合约间的函数调用
```

ERC20转账，不会触发receive和fallback（只是改变代币合约中的余额映射）。只有ETH转账的时候才会有这样的效果。

```solidity
// ETH 转账
(bool success, ) = payable(recipient).call{value: amount}("");  // 这会触发 receive()
```

call{value: amount}("")有数据的时候是fallback没有数据信息的时候是receive。

不管是ERC20还是ETH转账，只要不写require成功失败检查，就不会触发可能的回滚，失败就失败了，就被忽略了。



**2-xFn reentrancy**

```solidity
function withdraw() external nonReentrant {		
    require(balance[msg.sender] > 0, "No funds available!");

    (bool success, ) = payable(msg.sender).call{value: balance[msg.sender]}("");
    require(success, "Transfer failed" );

    balance[msg.sender] = 0; // Was it CEI or CIE? Not sure... :P
}
```

这个合约没有遵循CEI最佳实践， balance[msg.sender] = 0;数据更正应该在转账之前发生。即使该函数加了锁，但是重入攻击仍然可能奏效，攻击的是该函数的其他关联函数。

```solidity
// attacker
receive() external payable {
    uint256 amount = target.userBalance(address(this));
    console.log("Malicious contract received %s ETH but their deposit is still %s ETH!", msg.value/1 ether, amount/1 ether);
    target.transferTo(wallet, amount);
    console.log("Deposit transfered internally to Mallory");        
}

// origin
function transferTo(address recipient, uint256 amount) external { //nonReentrant could mitigate the exploit
    require(balance[msg.sender] >= amount, "Not enough funds to transfer!");
    balance[msg.sender] -= amount;
    balance[recipient] += amount;     
}
```

攻击链条是：

```solidity
// 攻击流程
withdraw() [locked] 
  └─> external call 
        └─> receive() 
              └─> transferTo() [not locked] // 可以执行，因为是另一个函数！
```

目前来说，最佳实践是除了只要涉及到共享状态变更，就要使用CEI原则。以及涉及共享状态变更就要加锁。



**3-Commit Reveal**

代码1的问题是计算hash值作为commit方式不对，

```solidity
// CommitReveal_1 的问题：可预计算
commitHash = keccak256(abi.encodePacked(bool, voter));  // 只有两种可能
```

voter这个地址是链上可公开的，那么bool类型的话只有两种可能。所有任何攻击者很容易就猜出来这个commit是多少了，从而使得commit没有意义。所以我们在生成commit之前要加一个salt。然后把这个作为commit提交，将来验证的时候也上链提交salt数据。

代码2的问题是答案的所有权可能被窃取。

```solidity
// CommitReveal_2 的问题：答案所有权
commitHash = keccak256(abi.encodePacked(answer, seed));  // 没有绑定提交者地址
```

CommitReveal_2 的漏洞利用流程：

```solidity
1. Alice 知道答案，准备提交：
   commitHash = keccak256(abi.encodePacked("正确答案", "随机数")); // reveal环节

2. Mallory 看到 Alice 的交易在 mempool 中，可以：
   - 前置运行（frontrun）Alice 的交易
   - 使用相同的 commitHash 提交
   - 等待答案公布后再提交相同的答案和随机数
   - 获得积分
```

解决办法就是做commit的时候要把自己的地址绑上去，这样reveal的时候有人想要抢跑答案也不行了。
