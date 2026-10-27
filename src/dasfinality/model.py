"""Canonical, operation-specific information model for a limited reference prototype.

This project does not claim a wire-format standard, safe cryptographic key custody,
operating-system integration, or an implementation of all disclosed embodiments.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any
import hashlib, json, hmac, math, copy

class Denied(Exception):
    """A requested consequential operation was withheld."""
class InvalidMessage(Denied):
    """Untrusted or non-canonical request/evidence was rejected."""
class AckLost(Exception):
    """Simulation of lost ACK AFTER a locally committed effect."""

def canonical(data: Any) -> bytes:
    def check(v):
        if v is None or isinstance(v,(str,bool,int)):
            return
        if isinstance(v,float):
            if not math.isfinite(v): raise InvalidMessage('non-finite value')
            # No floating-point effect parameters in this reference profile.
            raise InvalidMessage('floats disallowed; use strings/minor units')
        if isinstance(v,list):
            for x in v: check(x)
            return
        if isinstance(v,dict):
            if any(not isinstance(k,str) for k in v):raise InvalidMessage('non-string key')
            for x in v.values():check(x)
            return
        raise InvalidMessage('unsupported value type')
    check(data)
    try:
        return json.dumps(data,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf8')
    except (TypeError,ValueError) as e:
        raise InvalidMessage('canonical encoding failed') from e

def digest(data: Any) -> str:
    return hashlib.sha256(canonical(data)).hexdigest()

def mac(key:bytes, data:Any) -> str:
    return hmac.new(key,canonical(data),hashlib.sha256).hexdigest()

def secure_equal(a:str,b:str)->bool:
    return hmac.compare_digest(a,b)

@dataclass(frozen=True)
class Effect:
    """Actual effect descriptor, NOT a permission or proof of authority."""
    principal:str
    tenant:str
    resource:str
    operation:str
    params:dict
    sink_id:str
    route:str
    device:str
    grant_id:str
    nonce:str
    cost:int=1
    requires_effect_digest:str|None=None
    def __post_init__(self):
        for name in ('principal','tenant','resource','operation','sink_id','route','device','grant_id','nonce'):
            if not isinstance(getattr(self,name),str) or not getattr(self,name):
                raise InvalidMessage('nonempty string required: '+name)
        if not isinstance(self.cost,int) or isinstance(self.cost,bool) or self.cost<0:
            raise InvalidMessage('cost must be a nonnegative integer')
        if self.requires_effect_digest is not None and (
                not isinstance(self.requires_effect_digest,str)
                or len(self.requires_effect_digest)!=64
                or any(c not in '0123456789abcdef' for c in self.requires_effect_digest)):
            raise InvalidMessage('expected predecessor effect SHA-256 digest required')
        if not isinstance(self.params,dict): raise InvalidMessage('params must be a dictionary')
        object.__setattr__(self,'params',copy.deepcopy(self.params))
        canonical(asdict(self))
    @property
    def effect_digest(self)->str:return digest(asdict(self))

@dataclass(frozen=True)
class Enablement:
    """Bound protected-controller evidence; unusable without authentic gateway observation."""
    digest:str
    grant_id:str
    grant_generation:int
    owner_epoch:int
    policy_generation:int
    expiry:int
    sink_id:str
    nonce:str
    predecessor_receipt:str|None
    signature:str
    def claims(self)->dict:
        return {k:v for k,v in asdict(self).items() if k!='signature'}

@dataclass(frozen=True)
class ObservedOperation:
    """Authenticated observation from a configured trusted-side gateway adapter."""
    effect:Effect
    gateway_id:str
    signature:str
    def claims(self)->dict:
        return {'effect':asdict(self.effect),'gateway_id':self.gateway_id}
