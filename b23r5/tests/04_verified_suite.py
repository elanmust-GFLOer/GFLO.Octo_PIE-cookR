#!/usr/bin/env python3
"""Exact stdlib unittest enumeration and result oracle. No skip/expected failure allowed."""
import sys,runpy,unittest,json
if len(sys.argv)!=3:raise SystemExit("usage: suite.py FILE EXPECTED_COUNT")
source=sys.argv[1]; expected=int(sys.argv[2]);sys.argv=sys.argv[:1]
namespace=runpy.run_path(source,run_name="b23r5_test_module")
cases=unittest.defaultTestLoader.loadTestsFromModule(type(sys)("b23r5_test_module"))
module=type(sys)("b23r5_test_module")
module.__dict__.update(namespace)
cases=unittest.defaultTestLoader.loadTestsFromModule(module)
runner=unittest.TextTestRunner(verbosity=2)
count=cases.countTestCases()
print("MANIFEST",json.dumps({"source":source,"expected":expected,"discovered":count}),flush=True)
if count!=expected:raise SystemExit(f"wrong test inventory: {count} != {expected}")
result=runner.run(cases)
if result.testsRun!=expected or not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
 raise SystemExit("test ledger violates zero-skips, expected-failure, error/failure policy")
print(f"MANIFEST PASS {source} {expected}/{expected}",flush=True)
