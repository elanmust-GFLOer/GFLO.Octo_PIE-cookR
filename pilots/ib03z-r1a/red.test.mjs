// RED phase for independently reproduced F-01; MUST fail on original IB03X/Z.
import assert from 'node:assert/strict';
import {Interface,keccak256} from 'ethers';
import {pinnedVerifier} from '../ib03x/pinned.mjs';
import {verifySources} from '../ib03z/provenance.mjs';
const H='0x'+'ab'.repeat(32),J='0x'+'cd'.repeat(32);
const code='0x60006000f3',wallet='0x'+'ab'.repeat(20);
const abi=new Interface(['function isValidSignature(bytes32,bytes) view returns(bytes4)']);
const rpc=async (m,p)=>{
 if(m==='eth_chainId')return '0xaa36a7';
 if(m==='eth_getBlockByHash')return {number:'0x100',hash:H};
 if(m==='eth_getBlockByNumber')return {number:'0x100',hash:p[0]==='finalized'?J:H};
 if(m==='eth_getCode')return code;
 if(m==='eth_call')return abi.encodeFunctionResult('isValidSignature',['0x1626ba7e']);
 throw Error(m);
};
const verify=pinnedVerifier({rpc,wallet,blockHash:H,codeHash:keccak256(code)});
assert.equal(await verify({wallet,chainId:'11155111',digest:H,signature:'0x'+'00'.repeat(65)}),false,
 'F-01 X: contradictory same-height finalized hash must DENY');
await assert.rejects(()=>verifySources([rpc,rpc]),/IB03Z_BLOCK_/,
 'F-01 Z: contradictory same-height finalized hash must BLOCK');
console.log('F01_RED_REGRESSION_NOW_DENIES_CONTRADICTORY_FINALIZED_HASHES');
