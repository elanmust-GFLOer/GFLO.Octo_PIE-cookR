"""Read-only import of exact R6A sources. No repository or privilege mutation."""
from pathlib import Path
import subprocess
import sys

R6A_ROOT=Path(__file__).resolve().parent.parent/"gflo-r6a"
R6A_HEAD="12e2df4c32ef51d08c799ec63a565c90221e8bcd"
def check_anchor():
    head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=R6A_ROOT,text=True).strip()
    if head!=R6A_HEAD: raise RuntimeError("R6A anchor changed; stop review")
    subprocess.run(["git","diff","--exit-code","HEAD","--"],cwd=R6A_ROOT,check=True,capture_output=True)
check_anchor()
sys.path.insert(0,str(R6A_ROOT))

from b23r6a.gateway import Gateway
from b23r6a.workers import WorkerSupervisor
from b23r6a.contracts import Identity,SessionObservation,SessionState,UserObservation,LocalState,Rejected,Unavailable,ExpiredDeadline
from b23r6a.adapters.offline import OfflineJwtVerifier,OfflineUsers,OfflineSessions,OfflinePrimary,OfflineEmitter,FaultAdapter,test_token,USER_A,USER_B,SESSION_A
