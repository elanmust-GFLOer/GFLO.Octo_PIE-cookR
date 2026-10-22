"""Read-only observation batches, each killed/reaped before returning evidence.

Avoid seven interpreter startups inside a one-second authorization budget. No
request worker or adapter survives its batch. Every proof is still checked by
the parent; final observations remain after audit approval, under the fence.
"""
from .contracts import UserObservation,Unavailable

def invoke(adapter,method,args):
    if adapter is None:raise Unavailable()
    return getattr(adapter,method)(*args)

class InitialEvidence:
    def __init__(self,adapters,validate_identity):
        self.adapters,self.validate_identity=adapters,validate_identity
    def collect(self,args,call=invoke):
        (token,)=args
        identity=call(self.adapters.jwt,"verify",(token,))
        self.validate_identity(identity)
        user=call(self.adapters.user,"observe",(identity,))
        if type(user) is not UserObservation or user.subject!=identity.subject:
            return identity,user,None  # Parent rejects before using session.
        session=call(self.adapters.session,"observe",(identity,))
        return identity,user,session
    def verify(self,token):return self.collect((token,))

class FinalEvidence:
    def __init__(self,adapters):self.adapters=adapters
    def collect(self,args,call=invoke):
        identity,request,expected=args
        session=call(self.adapters.session,"observe",(identity,))
        if session!=expected:return session,None
        return session,call(self.adapters.policy,"authorize",(identity,request))
    def observe(self,identity,request,expected):return self.collect((identity,request,expected))
