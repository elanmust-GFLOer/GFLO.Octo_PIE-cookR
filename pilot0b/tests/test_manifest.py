from dataclasses import replace
import json
from pathlib import Path
import unittest
from pilot0b.manifest import *

NOW=1_000_000
ADDRESS="0x1111111111111111111111111111111111111111"
IMPL="0x2222222222222222222222222222222222222222"
OTHER="0x3333333333333333333333333333333333333333"
READ="0x70a08231"
ABI=json.dumps([{"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],
                 "outputs":[{"type":"uint256"}],"stateMutability":"view"}])

def fixture(proxy=False,legacy=False):
    addr=LEGACY_ADDRESS if legacy else ADDRESS
    kind="EIP1967" if proxy else "DIRECT"
    classification=SourceClass.LEGACY_UNTRUSTED_XP if legacy else SourceClass.DEMO_FIXTURE
    e=Evidence("fixture://independent-observation",11155111,addr,b'creation-fixture-bytes',b'runtime-fixture-bytes',ABI,
        b'synthetic-source-fixture',"fixture://source/core",kind,IMPL if proxy else None,b'implementation-fixture' if proxy else None,
        classification,(SelectorProof(READ,"balanceOf(address)"),),Verification.VERIFIED_OFFLINE,
        "fixture-reviewer:independent-config",NOW-1,NOW+60,legacy)
    impl=Implementation(IMPL,sha256(e.implementation_runtime)) if proxy else None
    m=Manifest(e.chain_id,e.contract,sha256(e.creation_code),sha256(e.runtime_code),sha256(abi_bytes(e.abi_json)),e.source_id,
        sha256(e.verified_source),kind,impl,classification,(READ,),e.reference,Verification.VERIFIED_OFFLINE,NOW-1,NOW+60)
    return m,e,ReadSource(e.chain_id,e.contract,(READ,))

class ManifestSecurity(unittest.TestCase):
    def setUp(self):self.m,self.e,self.request=fixture();self.registry=Registry((self.e,))
    def check(self,m=None,e=None,request=None,now=NOW):
        return validate(self.m if m is None else m,self.request if request is None else request,
                        self.registry if e is None else Registry((e,)),now)
    def deny(self,m=None,e=None,request=None,reason=None,now=NOW):
        r=self.check(m,e,request,now);self.assertEqual(r.status,"DENY")
        self.assertFalse(r.production_authorized);self.assertFalse(r.canonical_xp_authorized);self.assertEqual(r.entitlements,())
        if reason:self.assertEqual(r.reason,reason)
        return r
    def test_complete_synthetic_observation_is_consistent_only_offline(self):
        r=self.check();self.assertEqual(r.status,"CONSISTENT_OFFLINE_NON_PRODUCTION")
        self.assertEqual(r.classification,SourceClass.DEMO_FIXTURE);self.assertFalse(r.production_authorized)
        self.assertFalse(r.canonical_xp_authorized);self.assertEqual(r.entitlements,());self.assertEqual(len(r.manifest_digest),64)
    def test_missing_manifest_denied(self):self.assertEqual(validate(None,self.request,self.registry,NOW).status,"DENY")
    def test_missing_independent_registry_denied(self):
        self.assertEqual(validate(self.m,self.request,None,NOW).reason,"EVIDENCE_AUTHORITY_UNAVAILABLE")
    def test_caller_verified_flag_cannot_replace_evidence(self):
        self.assertEqual(validate(self.m,self.request,Registry(),NOW).reason,"EVIDENCE_MISSING")
    def test_wrong_chain(self):self.deny(request=replace(self.request,chain_id=1),reason="CHAIN_OR_CONTRACT_MISMATCH")
    def test_wrong_contract(self):self.deny(request=replace(self.request,contract=OTHER),reason="CHAIN_OR_CONTRACT_MISMATCH")
    def test_wrong_abi_hash(self):self.deny(m=replace(self.m,abi_hash=sha256(b'wrong')),reason="ABI_HASH_MISMATCH")
    def test_wrong_runtime_hash(self):self.deny(m=replace(self.m,runtime_hash=sha256(b'wrong')),reason="RUNTIME_HASH_MISMATCH")
    def test_wrong_deployment_hash(self):self.deny(m=replace(self.m,deployment_hash=sha256(b'wrong')),reason="DEPLOYMENT_HASH_MISMATCH")
    def test_wrong_source_hash(self):self.deny(m=replace(self.m,source_hash=sha256(b'wrong')),reason="SOURCE_HASH_MISMATCH")
    def test_missing_runtime_digest_is_not_fabricated(self):self.deny(m=replace(self.m,runtime_hash=None),reason="DIGEST_MISSING_OR_UNSUPPORTED")
    def test_keccak_label_cannot_be_substituted_for_sha256(self):
        self.deny(m=replace(self.m,runtime_hash=Hash('keccak256',self.m.runtime_hash.value)),reason="DIGEST_MISSING_OR_UNSUPPORTED")
    def test_source_identifier_conflict(self):self.deny(m=replace(self.m,source_id='fixture://other'),reason="EVIDENCE_CONFLICT")
    def test_unknown_manifest_verification(self):self.deny(m=replace(self.m,verification=Verification.UNKNOWN),reason="MANIFEST_UNVERIFIED")
    def test_revoked_evidence(self):self.deny(e=replace(self.e,verification=Verification.REVOKED),reason="EVIDENCE_UNVERIFIED")
    def test_missing_reviewer(self):self.deny(e=replace(self.e,reviewer_ref=''),reason="EVIDENCE_UNVERIFIED")
    def test_stale_manifest_at_exact_expiry(self):self.deny(now=self.m.expires_at,reason="MANIFEST_STALE")
    def test_stale_evidence_at_exact_expiry(self):self.deny(e=replace(self.e,expires_at=NOW),reason="EVIDENCE_STALE")
    def test_future_observation(self):self.deny(e=replace(self.e,observed_at=NOW+1),reason="EVIDENCE_STALE")
    def test_conflicting_registry_entries_fail_at_configuration(self):
        with self.assertRaises(ValueError):Registry((self.e,replace(self.e,runtime_code=b'conflicting')))
    def test_proxy_implementation_consistency(self):
        m,e,q=fixture(proxy=True)
        r=validate(m,q,Registry((e,)),NOW);self.assertEqual(r.status,"CONSISTENT_OFFLINE_NON_PRODUCTION")
        self.assertFalse(r.production_authorized)
    def test_proxy_implementation_address_mismatch(self):
        m,e,q=fixture(proxy=True);m=replace(m,implementation=replace(m.implementation,address=OTHER))
        self.assertEqual(validate(m,q,Registry((e,)),NOW).reason,"IMPLEMENTATION_ADDRESS_MISMATCH")
    def test_proxy_implementation_runtime_mismatch(self):
        m,e,q=fixture(proxy=True);m=replace(m,implementation=replace(m.implementation,runtime_hash=sha256(b'wrong')))
        self.assertEqual(validate(m,q,Registry((e,)),NOW).reason,"IMPLEMENTATION_HASH_MISMATCH")
    def test_proxy_missing_implementation(self):
        m,e,q=fixture(proxy=True)
        self.assertEqual(validate(replace(m,implementation=None),q,Registry((e,)),NOW).reason,"IMPLEMENTATION_MISSING")
    def test_direct_contract_cannot_sneak_in_implementation(self):
        self.deny(m=replace(self.m,implementation=Implementation(IMPL,sha256(b'impl'))),reason="PROXY_IMPLEMENTATION_CONFLICT")
    def test_unknown_proxy_kind_denied(self):
        self.deny(m=replace(self.m,proxy_kind='UNKNOWN'),e=replace(self.e,proxy_kind='UNKNOWN'),reason="PROXY_IDENTITY_UNVERIFIED")
    def test_permissionless_xp_is_untrusted_without_canonical_promotion(self):
        m,e,q=fixture(legacy=True);r=validate(m,q,Registry((e,)),NOW)
        self.assertEqual(r.status,"CONSISTENT_OFFLINE_NON_PRODUCTION")
        self.assertEqual(r.classification,SourceClass.LEGACY_UNTRUSTED_XP)
        self.assertFalse(r.canonical_xp_authorized);self.assertFalse(r.production_authorized);self.assertEqual(r.entitlements,())
    def test_permissionless_xp_on_other_address_cannot_be_demo(self):
        self.deny(e=replace(self.e,permissionless_xp=True),reason="LEGACY_PROMOTION_DENIED")
    def test_reviewed_classification_never_grants_production_or_xp(self):
        m=replace(self.m,classification=SourceClass.REVIEWED_PROTOCOL_DATA)
        e=replace(self.e,classification=SourceClass.REVIEWED_PROTOCOL_DATA)
        r=self.check(m,e);self.assertEqual(r.status,"CONSISTENT_OFFLINE_NON_PRODUCTION")
        self.assertFalse(r.production_authorized);self.assertFalse(r.canonical_xp_authorized);self.assertEqual(r.entitlements,())
    def test_legacy_review_label_cannot_promote(self):
        m,e,q=fixture(legacy=True);m=replace(m,classification=SourceClass.REVIEWED_PROTOCOL_DATA)
        e=replace(e,classification=SourceClass.REVIEWED_PROTOCOL_DATA)
        r=validate(m,q,Registry((e,)),NOW);self.assertEqual(r.status,"DENY");self.assertEqual(r.classification,SourceClass.LEGACY_UNTRUSTED_XP)
    def test_unknown_selector_denied(self):self.deny(request=replace(self.request,selectors=('0xdeadbeef',)),reason="SELECTOR_NOT_ALLOWED")
    def test_forged_selector_to_view_signature_mapping_denied(self):
        m=replace(self.m,read_selectors=('0xa9059cbb',));e=replace(self.e,selectors=(SelectorProof('0xa9059cbb','balanceOf(address)'),))
        self.deny(m,e,replace(self.request,selectors=('0xa9059cbb',)),reason="SELECTOR_UNVERIFIABLE")
    def test_nonpayable_mutation_selector_denied(self):
        abi=json.loads(ABI);abi[0]['stateMutability']='nonpayable';text=json.dumps(abi)
        self.deny(m=replace(self.m,abi_hash=sha256(abi_bytes(text))),e=replace(self.e,abi_json=text),reason="MUTATION_SELECTOR_DENIED")
    def test_manifest_cannot_request_production_authority(self):
        self.deny(m=replace(self.m,non_production=False),reason="PRODUCTION_AUTHORITY_PROHIBITED")
    def test_unknown_clock_fails_closed(self):self.deny(now=float('nan'),reason="CLOCK_INVALID")
    def test_conflicting_duplicate_abi_keys_fail_closed(self):
        text=ABI.replace('"stateMutability": "view"','"stateMutability":"nonpayable","stateMutability":"view"')
        self.deny(e=replace(self.e,abi_json=text),reason="MALFORMED_OR_UNCERTAIN_EVIDENCE")
    def test_real_legacy_manifest_remains_incomplete_and_denied(self):
        p=Path(__file__).resolve().parents[1]/'legacy-sepolia.incomplete.json'
        data=json.loads(p.read_text());self.assertEqual(data['classification'],'LEGACY_UNTRUSTED_XP')
        self.assertIsNone(data['runtime_hash']);self.assertIsNone(data['deployment_hash'])
        self.assertEqual(data['verification'],'UNKNOWN');self.assertFalse(data['production_authorized'])
        m=replace(self.m,chain_id=data['chain_id'],contract=data['contract'],
                  runtime_hash=None,deployment_hash=None,classification=SourceClass(data['classification']),
                  verification=Verification(data['verification']))
        r=validate(m,ReadSource(data['chain_id'],data['contract'],(READ,)),Registry(),NOW)
        self.assertEqual(r.status,'DENY');self.assertEqual(r.reason,'DIGEST_MISSING_OR_UNSUPPORTED')
        self.assertEqual(r.classification,SourceClass.LEGACY_UNTRUSTED_XP)
        self.assertFalse(r.production_authorized);self.assertFalse(r.canonical_xp_authorized)

if __name__=='__main__':unittest.main(verbosity=2)
