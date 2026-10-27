import assert from 'node:assert/strict';
import solc from 'solc';
import {Wallet,Interface,hashMessage,getCreateAddress,keccak256} from 'ethers';
import {createVM,runTx} from '@ethereumjs/vm';
import {createLegacyTx} from '@ethereumjs/tx';
import {Common,Sepolia,Hardfork} from '@ethereumjs/common';
import {createAddressFromPrivateKey,createAddressFromString,hexToBytes,bytesToHex,createAccount} from '@ethereumjs/util';
const source=`pragma solidity ^0.8.20;
contract Stateful1271 {
 address public owner;
 constructor(address first) { owner=first; }
 function rotateOwner(address next) external { require(msg.sender==owner, "NOT_OWNER"); owner=next; }
 function isValidSignature(bytes32 digest, bytes calldata sig) external view returns(bytes4){
  if(sig.length!=65)return 0xffffffff;
  bytes32 r;bytes32 s;uint8 v;
  assembly {r:=calldataload(sig.offset) s:=calldataload(add(sig.offset,32)) v:=byte(0,calldataload(add(sig.offset,64)))}
  if(v!=27&&v!=28)return 0xffffffff;
  return ecrecover(digest,v,r,s)==owner?bytes4(0x1626ba7e):bytes4(0xffffffff);
 }
}`;
const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'Stateful.sol':{content:source}},settings:{optimizer:{enabled:true,runs:200},evmVersion:'cancun',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
for(const e of compiled.errors??[])if(e.severity==='error')throw Error(e.formattedMessage);
const art=compiled.contracts['Stateful.sol'].Stateful1271,abi=new Interface(art.abi);
const common=new Common({chain:Sepolia,hardfork:Hardfork.Cancun}),vm=await createVM({common});
const deployer=Wallet.createRandom(),ownerA=Wallet.createRandom(),ownerB=Wallet.createRandom();
const depKey=hexToBytes(deployer.privateKey),aKey=hexToBytes(ownerA.privateKey),bKey=hexToBytes(ownerB.privateKey);
const dep=createAddressFromPrivateKey(depKey);
for(const pk of [depKey,aKey,bKey])await vm.stateManager.putAccount(createAddressFromPrivateKey(pk),createAccount({balance:10n**20n}));
async function tx(pk,nonce,data,to){
 const raw=createLegacyTx({nonce,gasPrice:2000000000n,gasLimit:1000000n,data:hexToBytes(data),...(to?{to:createAddressFromString(to)}:{})},{common}).sign(pk);
 return runTx(vm,{tx:raw});
}
const deploy=await tx(depKey,0n,'0x'+art.evm.bytecode.object+abi.encodeDeploy([ownerA.address]).slice(2));
assert.equal(Number(deploy.receipt.status),1);
const address=getCreateAddress({from:dep.toString(),nonce:0n}),target=createAddressFromString(address);
const codehash=keccak256(bytesToHex(await vm.stateManager.getCode(target)));
const msg='GFLO IB03Y disposable SIWE payload';
const digest=hashMessage(msg),aSig=await ownerA.signMessage(msg),bSig=await ownerB.signMessage(msg);
async function call(fn,args=[]){
 const out=await vm.evm.runCall({caller:dep,to:target,data:hexToBytes(abi.encodeFunctionData(fn,args)),gasLimit:500000n,isStatic:true});
 if(out.execResult.exceptionError)throw Error('EVM_REVERT');
 return abi.decodeFunctionResult(fn,bytesToHex(out.execResult.returnValue))[0];
}
const valid=async sig=>(await call('isValidSignature',[digest,sig]))==='0x1626ba7e';
const rootA=bytesToHex(await vm.stateManager.getStateRoot());
assert.equal(await call('owner'),ownerA.address);assert.equal(await valid(aSig),true);assert.equal(await valid(bSig),false);
console.log('PASS state A old owner valid, new owner denied');
const unauthorized=await tx(bKey,0n,abi.encodeFunctionData('rotateOwner',[ownerB.address]),address);
assert.equal(Number(unauthorized.receipt.status),0);
assert.equal(await call('owner'),ownerA.address);
const rotation=await tx(aKey,0n,abi.encodeFunctionData('rotateOwner',[ownerB.address]),address);
assert.equal(Number(rotation.receipt.status),1);
const rootB=bytesToHex(await vm.stateManager.getStateRoot());
assert.notEqual(rootA,rootB);
assert.equal(await call('owner'),ownerB.address);
assert.equal(await valid(aSig),false);assert.equal(await valid(bSig),true);
assert.equal(keccak256(bytesToHex(await vm.stateManager.getCode(target))),codehash);
console.log('PASS state B old owner denied, new valid, codehash invariant');
console.log('IB03Y_STATEFUL_1271_LOCAL_EVM_PASS production=BLOCK');
console.log(JSON.stringify({chainId:11155111,rootA,rootB,codehash,localEvm:true,actualSepoliaBlock:false}));
