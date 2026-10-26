import assert from 'node:assert/strict';
import {Interface,keccak256,Wallet,hashMessage,getCreateAddress} from 'ethers';
import solc from 'solc';
import {createVM,runTx} from '@ethereumjs/vm';
import {createLegacyTx} from '@ethereumjs/tx';
import {Common,Sepolia,Hardfork} from '@ethereumjs/common';
import {createAddressFromPrivateKey,createAddressFromString,hexToBytes,bytesToHex,createAccount} from '@ethereumjs/util';
import {pinnedVerifier} from '../ib03x/pinned.mjs';
// F-03: EIP-1271 signature is bytes, NOT restricted to 65 bytes by the gateway.
const testAbi=new Interface(['function isValidSignature(bytes32,bytes) view returns(bytes4)']);
const address='0x'+'ab'.repeat(20),blockHash='0x'+'cd'.repeat(32),code='0x60006000f3';
let calls=0;
const rpc=async(method,params)=>{
 if(method==='eth_chainId')return '0xaa36a7';
 if(method==='eth_getBlockByHash')return {hash:blockHash,number:'0x100'};
 if(method==='eth_getBlockByNumber')return {hash:blockHash,number:'0x100'};
 if(method==='eth_getCode')return code;
 if(method==='eth_call'){calls++;return testAbi.encodeFunctionResult('isValidSignature',['0x1626ba7e']);}
 throw Error('UNSUPPORTED');
};
const verifier=pinnedVerifier({rpc,wallet:address,blockHash,codeHash:keccak256(code)});
for(const n of [0,1,64,65,66,130]){
 const prior=calls;
 assert.equal(await verifier({wallet:address,chainId:'11155111',digest:'0x'+'ab'.repeat(32),signature:'0x'+'ab'.repeat(n)}),true);
 assert.equal(calls,prior+1);
}
const prior=calls;
assert.equal(await verifier({wallet:address,chainId:'11155111',digest:'0x'+'ab'.repeat(32),signature:'0x'+'ab'.repeat(4097)}),false);
assert.equal(calls,prior);
assert.equal(await verifier({wallet:address,chainId:'11155111',digest:'0x'+'ab'.repeat(32),signature:'0xgg'}),false);
console.log('PASS F-03 variable ERC1271 bytes transported to contract, >4096-byte and malformed bytes rejected');
// F-05: execute vulnerable zero owner AND secured version in actual Solidity/EthereumJS EVM.
const solidity=`pragma solidity ^0.8.20;
contract Vulnerable1271 {
 address public owner;
 constructor(address first){owner=first;}
 function isValidSignature(bytes32 h,bytes calldata sig) external view returns(bytes4) {
  if(sig.length!=65)return 0xffffffff;
  bytes32 r;bytes32 s;uint8 v;
  assembly {r:=calldataload(sig.offset) s:=calldataload(add(sig.offset,32)) v:=byte(0,calldataload(add(sig.offset,64)))}
  return ecrecover(h,v,r,s)==owner?bytes4(0x1626ba7e):bytes4(0xffffffff);
 }
}
contract Safe1271 {
 address public owner;
 constructor(address first){require(first!=address(0),"ZERO_OWNER");owner=first;}
 function rotateOwner(address next) external {require(msg.sender==owner,"NOT_OWNER");require(next!=address(0),"ZERO_OWNER");owner=next;}
 function isValidSignature(bytes32 h,bytes calldata sig) external view returns(bytes4) {
  if(sig.length!=65)return 0xffffffff;
  bytes32 r;bytes32 s;uint8 v;
  assembly {r:=calldataload(sig.offset) s:=calldataload(add(sig.offset,32)) v:=byte(0,calldataload(add(sig.offset,64)))}
  if(v!=27&&v!=28)return 0xffffffff;
  address recovered=ecrecover(h,v,r,s);
  return recovered!=address(0)&&recovered==owner?bytes4(0x1626ba7e):bytes4(0xffffffff);
 }
}`;
const out=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'Pair.sol':{content:solidity}},settings:{evmVersion:'cancun',optimizer:{enabled:true,runs:200},outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
for(const e of out.errors??[])if(e.severity==='error')throw Error(e.formattedMessage);
const contracts=out.contracts['Pair.sol'];
const common=new Common({chain:Sepolia,hardfork:Hardfork.Cancun});
const vm=await createVM({common});
const deployPk=hexToBytes('0x'+'a1'.repeat(32)),ownerPk=hexToBytes('0x'+'11'.repeat(32));
const deployer=createAddressFromPrivateKey(deployPk),ownerAddr=createAddressFromPrivateKey(ownerPk);
for(const addr of [deployer,ownerAddr])await vm.stateManager.putAccount(addr,createAccount({balance:10n**20n}));
const wallet=new Wallet('0x'+'11'.repeat(32));
async function tx(pk,nonce,data,to){
 const signed=createLegacyTx({nonce,gasLimit:1200000n,gasPrice:2000000000n,data:hexToBytes(data),...(to?{to:createAddressFromString(to)}:{})},{common}).sign(pk);
 return runTx(vm,{tx:signed});
}
async function deploy(contractName,initial,nonce){
 const a=contracts[contractName],iface=new Interface(a.abi);
 const d=await tx(deployPk,nonce,'0x'+a.evm.bytecode.object+iface.encodeDeploy([initial]).slice(2));
 return {status:Number(d.receipt.status),address:getCreateAddress({from:deployer.toString(),nonce}),iface};
}
async function invoke(x,method,args=[]){
 const response=await vm.evm.runCall({caller:deployer,to:createAddressFromString(x.address),data:hexToBytes(x.iface.encodeFunctionData(method,args)),gasLimit:500000n,isStatic:true});
 assert.equal(response.execResult.exceptionError,undefined);
 return x.iface.decodeFunctionResult(method,bytesToHex(response.execResult.returnValue))[0];
}
const zero='0x'+'00'.repeat(20),invalid='0x'+'00'.repeat(64)+'1b',digest=hashMessage('GFLO-R1C');
const vuln=await deploy('Vulnerable1271',zero,0n);assert.equal(vuln.status,1);
const exploit=await invoke(vuln,'isValidSignature',[digest,invalid]);
assert.equal(exploit,'0x1626ba7e');
console.log('RED REPRODUCED F-05: vulnerable zero owner returns ERC1271 magic for invalid r/s');
const rejected=await deploy('Safe1271',zero,1n);assert.equal(rejected.status,0);
const fixed=await deploy('Safe1271',wallet.address,2n);assert.equal(fixed.status,1);
assert.equal(await invoke(fixed,'isValidSignature',[digest,invalid]),'0xffffffff');
const legitimate=await wallet.signMessage('GFLO-R1C');
assert.equal(await invoke(fixed,'isValidSignature',[digest,legitimate]),'0x1626ba7e');
const wrongRotate=await tx(ownerPk,0n,new Interface(contracts.Safe1271.abi).encodeFunctionData('rotateOwner',[zero]),fixed.address);
assert.equal(Number(wrongRotate.receipt.status),0);
assert.equal(await invoke(fixed,'owner'),wallet.address);
console.log('GREEN F-05: zero deploy and zero rotation revert, recovered zero signer denied, real owner accepted');
console.log('IB03Z_R1C_ERC1271_SIG_GENERALITY_ZERO_OWNER_LAB_PASS production=BLOCK');
