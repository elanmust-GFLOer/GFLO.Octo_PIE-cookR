"""Exact named manifest runner. Counts alone cannot establish test identity."""
import importlib
import json
from pathlib import Path
import runpy
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def flatten(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite): yield from flatten(item)
        else: yield item

def names(suite):
    return sorted(type(t).__name__+"."+t._testMethodName for t in flatten(suite))

def validate(actual,expected):
    if actual!=sorted(expected) or len(actual)!=len(set(actual)):
        raise ValueError("exact test identities differ: "+repr({"actual":actual,"expected":sorted(expected)}))

class Ledger(unittest.TextTestResult):
    def startTest(self,test):
        super().startTest(test)
        self.entries.append({"test":type(test).__name__+"."+test._testMethodName,"status":"STARTED"})
    def addSuccess(self,test):
        self.entries[-1]["status"]="PASS";super().addSuccess(test)
    def addFailure(self,test,err):
        self.entries[-1]["status"]="FAIL";super().addFailure(test,err)
    def addError(self,test,err):
        self.entries[-1]["status"]="ERROR";super().addError(test,err)
    def addSkip(self,test,reason):
        self.entries[-1]["status"]="SKIPPED";super().addSkip(test,reason)
    def __init__(self,*args,**kwargs): super().__init__(*args,**kwargs);self.entries=[]

def main(source,expected_count=None):
    path=Path(source).resolve().relative_to(ROOT).as_posix()
    manifest=json.loads((ROOT/"b23r6a/test-manifest.json").read_text())
    expected=manifest[path]
    if expected_count is not None and len(expected)!=int(expected_count):
        raise SystemExit("manifest count disagrees with caller")
    if path.startswith(("b23r6a/","pilot0b/")):
        module=importlib.import_module(path[:-3].replace("/","."))
    else:
        module=type(sys)("b23r5_test_module")
        module.__dict__.update(runpy.run_path(str(ROOT/path),run_name=module.__name__))
    suite=unittest.defaultTestLoader.loadTestsFromModule(module)
    validate(names(suite),expected)
    print("MANIFEST",json.dumps({"source":path,"tests":expected}),flush=True)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Ledger).run(suite)
    out=ROOT/"evidence";out.mkdir(exist_ok=True)
    (out/(path.replace("/","_")+".json")).write_text(json.dumps({"source":path,"expected":expected,"executed":result.entries},indent=2)+"\n")
    if (result.testsRun!=len(expected) or not result.wasSuccessful() or result.skipped
            or result.expectedFailures or result.unexpectedSuccesses):
        raise SystemExit("ledger failed: failures/errors/skips/expected failures forbidden")
    print(f"MANIFEST PASS {path} {result.testsRun}/{len(expected)}",flush=True)

if __name__=="__main__":main(*sys.argv[1:])
