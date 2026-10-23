import type {Challenge as CoreChallenge,ProofObservation,Submission} from '../pilot0c/proof.cjs';
export type Challenge=CoreChallenge;
export interface EIP1193Provider{request(args:{method:string;params?:unknown[]}):Promise<unknown>;on?(event:string,fn:(value:unknown)=>void):void;removeListener?(event:string,fn:(value:unknown)=>void):void;}
export interface FixtureBridge{readonly mode:'SYNTHETIC_AUTOMATED';readonly provider:EIP1193Provider;session():Promise<{token:string;csrf:string}>;}
declare global{interface Window{__GFLO_SYNTHETIC_PILOT__?:FixtureBridge;}}

export interface ChallengeTransportInput{readonly wallet:string;readonly chainId:11155111;readonly requestId:string;readonly source:string;}
export type VerifyTransportInput=Submission;
export interface IdentityExplorerResult extends ProofObservation{readonly environment:'PILOT_0D1_LOCALHOST';readonly syntheticPie:Readonly<{classification:'DEMO_FIXTURE';demoXp:number;canonicalXp:null;historicalTier:null;path:readonly string[];note:string}>;}
