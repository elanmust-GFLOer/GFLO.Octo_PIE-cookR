// @ts-check
/** @typedef {{request(args:{method:string,params?:unknown[]}):Promise<unknown>,on?:(event:string,fn:(value:unknown)=>void)=>void,removeListener?:(event:string,fn:(value:unknown)=>void)=>void}} EIP1193Provider */
export const CHAIN='0xaa36a7';
/** No automatic injected-provider discovery. Only the explicitly supplied provider. */
export class WalletAdapter{
 /** @param {EIP1193Provider} provider @param {(message:string)=>boolean} confirm @param {()=>void} changed */
 constructor(provider,confirm,changed){this.provider=provider;this.confirm=confirm;this.changed=changed;this.version=0;this.address='';
  this.listener=()=>{this.version++;this.address='';this.changed();};
  for(const name of ['accountsChanged','chainChanged','disconnect'])provider.on?.(name,this.listener);
 }
 close(){for(const name of ['accountsChanged','chainChanged','disconnect'])this.provider.removeListener?.(name,this.listener);}
 /** @param {unknown} value */
 account(value){if(typeof value!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(value))throw Error('WALLET_INVALID');return value;}
 async connect(){const version=this.version;const accounts=await this.provider.request({method:'eth_requestAccounts'});if(!Array.isArray(accounts)||accounts.length!==1)throw Error('WALLET_INVALID');
  const address=this.account(accounts[0]);if(await this.provider.request({method:'eth_chainId'})!==CHAIN)throw Error('CHAIN_DENIED');await this.check(address);if(version!==this.version)throw Error('WALLET_CHANGED');this.address=address;return address;}
 /** @param {string} expected */
 async check(expected){const accounts=await this.provider.request({method:'eth_accounts'});if(!Array.isArray(accounts)||accounts.length!==1||this.account(accounts[0]).toLowerCase()!==expected.toLowerCase())throw Error('WALLET_CHANGED');
  if(await this.provider.request({method:'eth_chainId'})!==CHAIN)throw Error('CHAIN_DENIED');}
 /** @param {string} message @param {string} address */
 async signSiwe(message,address){const version=this.version;await this.check(address);if(!this.confirm('Sign the displayed SIWE message for this synthetic localhost proof?'))throw Error('SIGNING_DECLINED');
  const hex='0x'+Array.from(new TextEncoder().encode(message),b=>b.toString(16).padStart(2,'0')).join('');
  const signature=await this.provider.request({method:'personal_sign',params:[hex,address]});await this.check(address);
  if(version!==this.version)throw Error('WALLET_CHANGED');if(typeof signature!=='string')throw Error('SIGNATURE_INVALID');return signature;}
 /** @param {{domain:object,types:object,message:object}} typed @param {string} address */
 async signConsent(typed,address){const version=this.version;await this.check(address);if(!this.confirm('Sign the separately displayed ID–Entity consent? Read-only proof only; no binding or XP rights.'))throw Error('SIGNING_DECLINED');
  const payload={domain:typed.domain,types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'},{name:'salt',type:'bytes32'}],...typed.types},primaryType:'BindingConsent',message:typed.message};
  const signature=await this.provider.request({method:'eth_signTypedData_v4',params:[address,JSON.stringify(payload)]});await this.check(address);
  if(version!==this.version)throw Error('WALLET_CHANGED');if(typeof signature!=='string')throw Error('SIGNATURE_INVALID');return signature;}
}
