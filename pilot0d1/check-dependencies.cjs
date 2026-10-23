'use strict';
const fs=require('node:fs'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const lock=require('./package-lock.json');
const expected={playwright:'1.56.1','playwright-core':'1.56.1',typescript:'5.9.3',fsevents:'2.3.2'};
for(const [name,version] of Object.entries(expected)){
 const entry=lock.packages['node_modules/'+name];
 if(entry.version!==version||entry.resolved!==`https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`||!/^sha512-[A-Za-z0-9+/]+=*$/.test(entry.integrity))throw Error('DEPENDENCY_PIN_MISMATCH');
 if(process.argv.includes('--registry')){
  // Registry metadata only: no install script or package code executes here.
  const result=spawnSync('npm',['view',`${name}@${version}`,'dist.integrity','--json','--fetch-retries=0','--fetch-timeout=20000'],{encoding:'utf8',timeout:25000});
  if(result.status!==0||JSON.parse(result.stdout)!==entry.integrity)throw Error('REGISTRY_INTEGRITY_MISMATCH');
 }
}
if(process.argv.includes('--installed'))for(const name of ['playwright','playwright-core','typescript'])if(require(name+'/package.json').version!==expected[name])throw Error('INSTALLED_VERSION_MISMATCH');
console.log('PILOT_0D1 DEPENDENCY PINS VERIFIED');
