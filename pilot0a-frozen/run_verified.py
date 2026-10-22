"""Local exact-name evidence runner; no network or repository mutations."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys
import unittest

ROOT=Path(__file__).resolve().parent

class Ledger(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.entries=[]
    def startTest(self,t):
        super().startTest(t)
        self.entries.append({"name":t.id(),"status":"STARTED","kind":"SOURCE_ORACLE" if type(t).__name__=="SourceCompatibility" else "SYNTHETIC_BEHAVIOR"})
    def addSuccess(self,t):self.entries[-1]["status"]="PASS";super().addSuccess(t)
    def addFailure(self,t,e):self.entries[-1]["status"]="FAIL";super().addFailure(t,e)
    def addError(self,t,e):self.entries[-1]["status"]="ERROR";super().addError(t,e)
    def addSkip(self,t,r):self.entries[-1]["status"]="SKIPPED";super().addSkip(t,r)

def flatten(suite):
    for t in suite:
        if isinstance(t,unittest.TestSuite):yield from flatten(t)
        else:yield t

def main():
    hashes=json.loads((ROOT/"file-manifest.json").read_text())
    for name,expected in hashes.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected:
            raise SystemExit("Source fingerprint mismatch: "+name)
    import test_pilot
    suite=unittest.defaultTestLoader.loadTestsFromModule(test_pilot)
    names=sorted(t.id() for t in flatten(suite))
    expected=json.loads((ROOT/"test-manifest.json").read_text())
    if names!=expected or len(names)!=len(set(names)):raise SystemExit("Exact test inventory changed")
    result=unittest.TextTestRunner(verbosity=2,resultclass=Ledger).run(suite)
    passed=result.wasSuccessful() and result.testsRun==len(expected) and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    payload={"status":"PASS" if passed else "FAIL","executed":result.testsRun,"expected":len(expected),
             "python":sys.version,"platform":platform.platform(),"PyJWT":importlib.metadata.version("PyJWT"),
             "tests":result.entries,"limits":["NO EVM test execution","NO live Auth/wallet verification","R6A original 1-second requirement OPEN","source/runtime tests are different evidence classes"],
             "known_finding_tests":["test_pilot.SourceCompatibility.test_legacy_gainxp_is_permissionless_source_oracle",
                "test_pilot.SourceCompatibility.test_r6a_accepts_read_beyond_original_one_second_budget",
                "test_pilot.SourceCompatibility.test_deployment_script_points_at_a_different_abi"]}
    (ROOT/"evidence/test-ledger.json").write_text(json.dumps(payload,indent=2)+"\n")
    if not passed:raise SystemExit("FAIL: no skips/expected failures accepted")
    print(f"PILOT_0A EXACT MANIFEST PASS {result.testsRun}/{len(expected)}; production BLOCKED")

if __name__=="__main__":main()
