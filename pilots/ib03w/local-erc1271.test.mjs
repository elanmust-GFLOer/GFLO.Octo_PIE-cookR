// GFLO IB-03W — real EIP-191 EOA and EIP-1271 Solidity execution on isolated Sepolia EVM.
// TEST-ONLY EOA keys, no network RPC, no deployment, no signing with user wallets.
import assert from 'node:assert/strict';
import solc from 'solc';
import {Wallet,Interface,hashMessage,verifyMessage,getCreateAddress} from 'ethers';
import {createVM,runTx} from '@ethereumjs/vm';
import {createLegacyTx} from '@ethereumjs/tx';
import {Common,Sepolia,Hardfork} from '@ethereumjs/common';
import {createAddressFromPrivateKey,createAddressFromString,hexToBytes,bytesToHex,createAccount} from '@ethereumjs/util';
import {verifySiweCore,parseSiwe} from '../ib03d/siwe-core.mjs';
const source=`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract IB03WLocal1271 {
  address public immutable owner;
  bytes4 constant MAGIC=0x1626ba7e;
  constructor(address signer){owner=signer;}
  function isValidSignature(bytes32 digest,bytes calldata signature) external view returns(bytes4) {
    if(signature.length!=65)return 0xffffffff;
    bytes32 r;bytes32 s;uint8 v;
    assembly {
      r:=calldataload(signature.offset)
      s:=calldataload(add(signature.offset,32))
      v:=byte(0,calldataload(add(signature.offset,64)))
    }
    if(v!=27&&v!=28)return 0xffffffff;
    return ecrecover(digest,v,r,s)==owner?MAGIC:bytes4(0xffffffff);
  }
}`;
const comp=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'Lab1271.sol':{content:source}},
 settings:{optimizer:{enabled:true,runs:200},evmVersion:'cancun',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
for(const e of comp.errors??[])if(e.severity==='error')throw Error(e.formattedMessage);
const art=comp.contracts['Lab1271.sol'].IB03WLocal1271;
const iface=new Interface(art.abi);
const common=new Common({chain:Sepolia,hardfork:Hardfork.Cancun});
assert.equal(Number(common.chainId()),11155111,'must run on Sepolia chain identity');
const vm=await createVM({common}),pk=hexToBytes('0x'+'a1'.repeat(32)),origin=createAddressFromPrivateKey(pk);
await vm.stateManager.putAccount(origin,createAccount({balance:10n**20n}));
const owner=new Wallet('0x'+'11'.repeat(32));
const bad=new Wallet('0x'+'22'.repeat(32));
const deployment='0x'+art.evm.bytecode.object+iface.encodeDeploy([owner.address]).slice(2);
const tx=createLegacyTx({nonce:0n,gasLimit:1000000n,gasPrice:2000000000n,data:hexToBytes(deployment)},{common}).sign(pk);
const receipt=await runTx(vm,{tx});
assert.equal(Number(receipt.receipt.status),1);
const contract=getCreateAddress({from:origin.toString(),nonce:0n});
assert.ok((await vm.stateManager.getCode(createAddressFromString(contract))).length>0);
const issued='2026-10-25T12:00:00Z',now=Date.parse('2026-10-25T12:01:00Z');
const nonce='GFLOWallet1234',domain='example.test',uri='https://example.test/login',chain='11155111';
const message=addr=>[domain+' wants you to sign in with your Ethereum account:',addr,'',
 'GFLO OctoPass IB-03W real cryptographic wallet evidence','',
 'URI: '+uri,'Version: 1','Chain ID: '+chain,'Nonce: '+nonce,'Issued At: '+issued].join('\n');
const expected={domain,uri,nonce,chainId:chain,maxAgeSeconds:600};
const eoa=message(owner.address),eoaSig=await owner.signMessage(eoa);
assert.equal(verifyMessage(eoa,eoaSig),owner.address);
let result=await verifySiweCore({message:eoa,signature:eoaSig,expected,now,accountKind:'EOA'});
assert.equal(result.ok,true);
assert.equal(result.sessionAuthorized,false);
assert.equal(result.nonceConsumed,false);
assert.equal((await verifySiweCore({message:eoa,signature:await bad.signMessage(eoa),expected,now,accountKind:'EOA'})).ok,false);
assert.equal((await verifySiweCore({message:eoa.replace('Chain ID: 11155111','Chain ID: 1'),signature:eoaSig,expected,now})).ok,false);
console.log('PASS EIP-191 EOA real secp256k1 sign/recover; wrong signer and chain denied');
const walletMessage=message(contract),walletSig=await owner.signMessage(walletMessage);
const expectedDigest=hashMessage(walletMessage);
const signerProof={address:owner.address,hash:expectedDigest,signature:walletSig};
assert.equal(parseSiwe(walletMessage).address.toLowerCase(),contract.toLowerCase());
let calls=0;
async function call1271({wallet,chainId,digest,signature},opts={}){
 calls++;
 assert.equal(chainId,'11155111');
 const target=createAddressFromString(wallet),data=iface.encodeFunctionData('isValidSignature',[digest,signature]);
 const resp=await vm.evm.runCall({caller:origin,to:target,gasLimit:500000n,data:hexToBytes(data),isStatic:true});
 if(resp.execResult.exceptionError)throw Error('EVM_REVERT');
 const [magic]=iface.decodeFunctionResult('isValidSignature',bytesToHex(resp.execResult.returnValue));
 return {magic,finalized:opts.finalized??true,blockHash:opts.blockHash??('0x'+'cd'.repeat(32))};
}
const adapter={verifyAtBlock:async p=>{
 if(p.wallet.toLowerCase()!==contract.toLowerCase())throw Error('WRONG_TARGET');
 if(p.digest!==expectedDigest)throw Error('DIGEST_MISMATCH');
 return call1271(p);
}};
result=await verifySiweCore({message:walletMessage,signature:walletSig,expected,now,accountKind:'ERC1271',erc1271:adapter});
assert.equal(result.ok,true);assert.equal(result.sessionAuthorized,false);
assert.ok(calls>0);
assert.equal((await verifySiweCore({message:walletMessage,signature:await bad.signMessage(walletMessage),expected,now,accountKind:'ERC1271',erc1271:adapter})).ok,false);
assert.equal((await verifySiweCore({message:walletMessage,signature:walletSig,expected,now,accountKind:'EOA'})).ok,false);
assert.equal((await verifySiweCore({message:walletMessage,signature:walletSig,expected:{...expected,chainId:'1'},now,accountKind:'ERC1271',erc1271:adapter})).ok,false);
const unfinalized={verifyAtBlock:p=>call1271(p,{finalized:false})};
assert.equal((await verifySiweCore({message:walletMessage,signature:walletSig,expected,now,accountKind:'ERC1271',erc1271:unfinalized})).ok,false);
const brokenHash={verifyAtBlock:p=>call1271(p,{blockHash:'bad'})};
assert.equal((await verifySiweCore({message:walletMessage,signature:walletSig,expected,now,accountKind:'ERC1271',erc1271:brokenHash})).ok,false);
console.log('PASS Solidity ERC-1271 ecrecover magic on Sepolia local EVM; invalid signer/finality/chain denied');
console.log('IB03W_REAL_EOA_LOCAL_ERC1271_EVM_PASS production=BLOCK');
console.log(JSON.stringify({chainId:11155111,solc:solc.version(),localContract:contract,signer:owner.address,hash:expectedDigest,signature:walletSig,localEvm:true,notLiveOnChain:true,notActualFinalityProof:true}));
