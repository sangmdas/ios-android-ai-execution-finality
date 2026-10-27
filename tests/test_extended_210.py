"""210 additional executable assertions organized as ten 21-case security matrices.

These tests validate ONLY the local Python/SQLite reference model; they do
not claim real iOS, Android, TEE/HSM, remote-effect or all-embodiment coverage.
Each pytest case has a stable descriptive ID for public reproducibility.
"""
from dataclasses import replace
from itertools import combinations
import pytest
from dasfinality import Denied, InvalidMessage, AckLost
from dasfinality.model import digest

# 1. Canonical descriptors: key order, types, arrays, Unicode and nesting.
CANONICAL_PAIRS = [
 ('top-level-key-order', {'a':1,'b':2}, {'b':2,'a':1}, True),
 ('nested-key-order', {'outer':{'a':1,'b':2}}, {'outer':{'b':2,'a':1}}, True),
 ('list-order', {'x':[1,2,3]}, {'x':[3,2,1]}, False),
 ('list-duplicate', {'x':[1,1]}, {'x':[1]}, False),
 ('missing-vs-null', {'x':None}, {}, False),
 ('boolean-vs-integer', {'x':True}, {'x':1}, False),
 ('zero-vs-false', {'x':0}, {'x':False}, False),
 ('empty-list-vs-object', {'x':[]}, {'x':{}}, False),
 ('empty-string-vs-null', {'x':''}, {'x':None}, False),
 ('case-sensitive', {'x':'Allow'}, {'x':'allow'}, False),
 ('unicode-same', {'x':'東京'}, {'x':'東京'}, True),
 ('unicode-composed-vs-decomposed', {'x':'é'}, {'x':'e\u0301'}, False),
 ('negative-vs-positive', {'x':-2}, {'x':2}, False),
 ('zero-vs-negative-one', {'x':0}, {'x':-1}, False),
 ('nested-array-swap', {'x':[[1,2],[3,4]]}, {'x':[[3,4],[1,2]]}, False),
 ('array-nested-key-order', {'x':[{'a':1,'b':2}]}, {'x':[{'b':2,'a':1}]}, True),
 ('path-traversal-literal', {'path':'/a/../b'}, {'path':'/b'}, False),
 ('recipient-case', {'recipient':'A@EXAMPLE'}, {'recipient':'a@example'}, False),
 ('name-vs-alias', {'resource':'file-A'}, {'resource':'alias-A'}, False),
 ('different-tenant', {'tenant':'A'}, {'tenant':'B'}, False),
 ('distinct-command-byte', {'command':'send'}, {'command':'send '}, False),
]
assert len(CANONICAL_PAIRS) == 21
@pytest.mark.parametrize('case_id,left,right,equal', CANONICAL_PAIRS, ids=[x[0] for x in CANONICAL_PAIRS])
def test_x01_canonical_operation_semantics(case_id,left,right,equal):
    assert (digest(left) == digest(right)) is equal

# 2. Strict input validation: schema and recursively rejected input types.
MALFORMED_EFFECTS = [
 ('empty-principal',{'principal':''}),('none-principal',{'principal':None}),
 ('integer-tenant',{'tenant':123}),('empty-resource',{'resource':''}),
 ('list-operation',{'operation':['WRITE']}),('empty-sink',{'sink_id':''}),
 ('empty-route',{'route':''}),('empty-device',{'device':''}),
 ('empty-grant',{'grant_id':''}),('empty-nonce',{'nonce':''}),
 ('negative-cost',{'cost':-1}),('boolean-cost',{'cost':True}),
 ('string-cost',{'cost':'1'}),('float-cost',{'cost':1.0}),
 ('list-params',{'params':['body']}),('nonstring-param-key',{'params':{1:'bad'}}),
 ('nested-bytes',{'params':{'deep':{'payload':b'x'}}}),
 ('nested-set',{'params':{'deep':[{'bad':{1,2}}]}}),
 ('invalid-digest-short',{'requires_effect_digest':'a'*63}),
 ('invalid-digest-upper',{'requires_effect_digest':'F'*64}),
 ('invalid-digest-number',{'requires_effect_digest':99}),
]
assert len(MALFORMED_EFFECTS)==21
@pytest.mark.parametrize('case_id,changes',MALFORMED_EFFECTS,ids=[x[0] for x in MALFORMED_EFFECTS])
def test_x02_untrusted_candidate_schema_rejected(mk,case_id,changes):
    with pytest.raises(InvalidMessage): mk(**changes)

# 3. Upstream authority profile: each profile has a distinct resource/operation/route
# policy and a concrete operation, not just a changed nonce.
RESOURCE_CHOICES = ['file-A','file-B','vault-A','ledger-A','device-A']
OP_CHOICES = ['WRITE','READ','SEND','PAY','ACTUATE']
ROUTE_CHOICES = ['api','ipc','socket','hardware']
SCOPE_PROFILES = []
for i in range(21):
    resource=RESOURCE_CHOICES[i % 5]
    operation=OP_CHOICES[(i//5 + i)%5]
    route=ROUTE_CHOICES[(i//4 + i)%4]
    # rotate exactly one denied scope dimension; one in four profiles is valid
    denied_dimension = ['none','resource','operation','route'][i%4]
    resources=[resource] if denied_dimension!='resource' else ['unrelated-resource']
    operations=[operation] if denied_dimension!='operation' else ['UNRELATED']
    routes=[route] if denied_dimension!='route' else ['unrelated-route']
    SCOPE_PROFILES.append((f'{i:02d}-{denied_dimension}-{operation}-{route}', resources,operations,routes,resource,operation,route,denied_dimension=='none'))
assert len(SCOPE_PROFILES)==21
@pytest.mark.parametrize('case_id,resources,operations,routes,resource,operation,route,authorized',SCOPE_PROFILES,ids=[x[0] for x in SCOPE_PROFILES])
def test_x03_grant_scopes_independently_checked(rig,mk,case_id,resources,operations,routes,resource,operation,route,authorized):
    rig.create_grant(grant_id='bounded',resources=resources,operations=operations,routes=routes,
                     expires=1500, budget=30)
    effect=mk(grant_id='bounded',resource=resource,operation=operation,route=route,nonce='scope-'+case_id)
    if authorized:
        cap=rig.issue(effect)
        assert rig.sink().effectuate(cap,rig.gateway().observe(effect))=='event:scope-'+case_id
    else:
        with pytest.raises(Denied):rig.issue(effect)
        assert rig.effect_count()==0

# 4. Authentic gateway observations can still indicate changed actual effect
# semantics; every changed operation must be denied and burn its authorized nonce.
MATERIAL_CHANGES = [
 ('body-value',{'body':'changed'}),('body-empty',{'body':''}),
 ('recipient-change',{'body':'authorized','recipient':'outsider'}),
 ('routing-change',{'body':'authorized','routing':'alternate'}),
 ('file-version',{'body':'authorized','version':9}),
 ('method-change',{'body':'authorized','method':'DELETE'}),
 ('empty-body-object',{}),('null-body',{'body':None}),
 ('list-body',{'body':['authorized']}),('nested-body',{'body':{'text':'authorized'}}),
 ('linebreak',{'body':'authorized\n'}),('uppercase-body',{'body':'AUTHORIZED'}),
 ('unicode-spoof',{'body':'authоrized'}),('amount-change',{'body':'authorized','amount_minor':1200}),
 ('different-currency',{'body':'authorized','currency':'EUR'}),
 ('destination-host',{'body':'authorized','host':'evil.example'}),
 ('resolved-ip',{'body':'authorized','resolved_ip':'198.51.100.12'}),
 ('path-redirect',{'body':'authorized','path':'/other'}),
 ('extra-header',{'body':'authorized','headers':{'x-role':'admin'}}),
 ('scope-claim',{'body':'authorized','scope':'global'}),
 ('signature-flag',{'body':'authorized','signed':True}),
]
assert len(MATERIAL_CHANGES)==21
@pytest.mark.parametrize('case_id,params',MATERIAL_CHANGES,ids=[x[0] for x in MATERIAL_CHANGES])
def test_x04_sink_reconstructs_actual_effect(rig,mk,case_id,params):
    authorized=mk(nonce='semantic-'+case_id)
    cap=rig.issue(authorized)
    actual=mk(nonce=authorized.nonce,params=params)
    with pytest.raises(Denied,match='actual operation differs'):
        rig.sink().effectuate(cap,rig.gateway().observe(actual))
    assert rig.state(authorized.nonce)['status']=='DENIED'
    assert rig.spent('grant-1')==0

# 5. Protected enablement signatures cover combinations of two independent fields.
TAMPER_FIELDS = {
    'digest':'d'*64,'grant_id':'different','grant_generation':42,
    'owner_epoch':77,'policy_generation':88,'expiry':500,
    'sink_id':'redirected-sink',
}
TAMPER_PAIRS=list(combinations(TAMPER_FIELDS,2))
assert len(TAMPER_PAIRS)==21
@pytest.mark.parametrize('field_a,field_b',TAMPER_PAIRS,ids=['+'.join(x) for x in TAMPER_PAIRS])
def test_x05_multifield_enablement_tampering_cannot_poison_state(rig,mk,field_a,field_b):
    effect=mk();legitimate=rig.issue(effect)
    forged=replace(legitimate,**{field_a:TAMPER_FIELDS[field_a],field_b:TAMPER_FIELDS[field_b]})
    with pytest.raises(InvalidMessage):rig.sink().effectuate(forged,rig.gateway().observe(effect))
    assert rig.state(effect.nonce) is None
    assert rig.sink().effectuate(legitimate,rig.gateway().observe(effect))=='event:test-0001'

# 6. Tampering the gateway-signed observation is different from the *gateway
# truthfully observing* an unauthorized operation tested above. Forgery must not
# consume valid protected authority.
FORGED_OBSERVATIONS = [
 ('new-principal',{'principal':'other-user'}),('new-tenant',{'tenant':'other-tenant'}),
 ('new-resource',{'resource':'file-B'}),('new-operation',{'operation':'SEND'}),
 ('new-route',{'route':'socket'}),('new-sink',{'sink_id':'other-sink'}),
 ('new-device',{'device':'device-2'}),('new-grant',{'grant_id':'other-grant'}),
 ('new-nonce',{'nonce':'evil'}),('new-cost',{'cost':2}),
 ('new-body',{'params':{'body':'evil'}}),('new-recipient',{'params':{'recipient':'evil'}}),
 ('new-target',{'params':{'target':'other'}}),('new-scope',{'params':{'scope':'all'}}),
 ('new-version',{'params':{'version':3}}),('empty-params',{'params':{}}),
 ('zero-cost',{'cost':0}),('large-cost',{'cost':99}),
 ('extra-param',{'params':{'body':'authorized','extra':'new'}}),
 ('unicode-change',{'params':{'body':'аuthorized'}}),
 ('different-route-and-target',{'route':'hardware','resource':'ledger-A'}),
]
assert len(FORGED_OBSERVATIONS)==21
@pytest.mark.parametrize('case_id,changes',FORGED_OBSERVATIONS,ids=[x[0] for x in FORGED_OBSERVATIONS])
def test_x06_observation_mutation_without_reauthentication(rig,mk,case_id,changes):
    from dataclasses import replace
    effect=mk();cap=rig.issue(effect);obs=rig.gateway().observe(effect)
    forged=replace(obs,effect=mk(**changes))
    with pytest.raises(InvalidMessage):rig.sink().effectuate(cap,forged)
    assert rig.state(effect.nonce) is None
    assert rig.effect_count()==0

# 7. Clock boundary and enablement expiry tests (21 distinct TTL/clock profiles).
CLOCK_PROFILES = [
 (1,0),(1,1),(2,1),(2,2),(3,4),(5,2),(5,5),(8,7),
 (8,9),(10,10),(15,14),(15,16),(30,29),(30,30),(45,46),
 (60,59),(60,61),(90,90),(120,119),(120,121),(150,100),
]
assert len(CLOCK_PROFILES)==21
@pytest.mark.parametrize('ttl,offset',CLOCK_PROFILES,ids=[f'ttl-{t}-offset-{o}' for t,o in CLOCK_PROFILES])
def test_x07_strict_enablement_expiry_boundary(rig,mk,ttl,offset):
    clock=[1000];rig.now=lambda:clock[0]
    e=mk();cap=rig.issue(e,ttl=ttl);clock[0]+=offset
    if offset<ttl:
        assert rig.sink().effectuate(cap,rig.gateway().observe(e))
        assert rig.spent('grant-1')==1
    else:
        with pytest.raises(Denied,match='expired'):rig.sink().effectuate(cap,rig.gateway().observe(e))
        assert rig.effect_count()==0

# 8. TWO prepared requests for one bounded grant: at preparation both may
# appear affordable; only the current atomic sink-local budget may permit both.
QUOTA_PAIRS = [
 (0,0,0),(1,0,1),(1,1,0),(1,1,1),(2,1,1),(2,2,1),(3,1,3),
 (3,2,1),(4,2,3),(5,3,2),(5,3,3),(6,1,6),(7,4,3),(7,4,4),
 (8,5,3),(9,6,6),(10,5,5),(10,8,3),(12,11,2),(15,7,9),(20,12,8),
]
assert len(QUOTA_PAIRS)==21
@pytest.mark.parametrize('budget,first,second',QUOTA_PAIRS,ids=[f'budget-{b}-costs-{a}-{c}' for b,a,c in QUOTA_PAIRS])
def test_x08_atomic_budget_current_at_effectuation(rig,mk,budget,first,second):
    rig.update_budget('grant-1',budget)
    first_effect=mk(nonce='q-first',cost=first)
    second_effect=mk(nonce='q-second',cost=second)
    first_cap=rig.issue(first_effect)
    # Preparation may be refused immediately when individually over quota.
    if second>budget:
        with pytest.raises(Denied):rig.issue(second_effect)
        rig.sink().effectuate(first_cap,rig.gateway().observe(first_effect))
        assert rig.effect_count()==1
        assert rig.spent('grant-1')==first
        return
    second_cap=rig.issue(second_effect)
    rig.sink().effectuate(first_cap,rig.gateway().observe(first_effect))
    if first+second<=budget:
        rig.sink().effectuate(second_cap,rig.gateway().observe(second_effect))
        assert rig.effect_count()==2
        assert rig.spent('grant-1')==first+second
    else:
        with pytest.raises(Denied,match='quota exceeded'):
            rig.sink().effectuate(second_cap,rig.gateway().observe(second_effect))
        assert rig.state('q-second')['status']=='DENIED'
        assert rig.effect_count()==1
        assert rig.spent('grant-1')==first

# 9. A real local mock predecessor is required; accepted receipts are scoped
# to each *exact* committed effect, despite diverse resources / operations.
CAUSAL_PREDECESSORS = [
 (i, RESOURCE_CHOICES[i%5],OP_CHOICES[(i//5+i)%5],ROUTE_CHOICES[(i//3+i)%4])
 for i in range(21)
]
assert len(CAUSAL_PREDECESSORS)==21
@pytest.mark.parametrize('number,resource,operation,route',CAUSAL_PREDECESSORS,ids=[f'{i:02d}-{r}-{o}-{rt}' for i,r,o,rt in CAUSAL_PREDECESSORS])
def test_x09_exact_predecessor_receipt_matches_operation(rig,mk,number,resource,operation,route):
    pred=mk(nonce=f'predecessor-{number}',resource=resource,operation=operation,route=route)
    event=rig.sink().effectuate(rig.issue(pred),rig.gateway().observe(pred))
    receipt=rig.receipt(event)
    successor=mk(nonce=f'successor-{number}',requires_effect_digest=pred.effect_digest)
    cap=rig.issue(successor,predecessor_receipt=receipt)
    assert rig.sink().effectuate(cap,rig.gateway().observe(successor))=='event:successor-'+str(number)
    wrong=mk(nonce=f'different-predecessor-{number}',resource=resource,operation=operation,route=route)
    unauthorized=mk(nonce=f'wrong-successor-{number}',requires_effect_digest=wrong.effect_digest)
    with pytest.raises(Denied,match='different predecessor'):
        rig.issue(unauthorized,predecessor_receipt=receipt)

# 10. Crash/ACK failures across multiple authorized effect families: the
# mock SQLite mutation is atomic with consumption and survives retry policy.
CRASH_EFFECTS = [
 ('file-A','WRITE','api'),('file-B','READ','ipc'),('vault-A','SEND','socket'),
 ('ledger-A','PAY','api'),('device-A','ACTUATE','hardware'),
 ('file-B','WRITE','hardware'),('vault-A','READ','ipc'),
]
CRASH_MATRIX = [(stage,r,o,route) for stage in ('precommit','ack-lost','normal') for r,o,route in CRASH_EFFECTS]
assert len(CRASH_MATRIX)==21
@pytest.mark.parametrize('stage,resource,operation,route',CRASH_MATRIX,ids=[f'{stage}-{op}-{res}-{route}' for stage,res,op,route in CRASH_MATRIX])
def test_x10_crash_and_ack_boundary_is_atomic(rig,mk,stage,resource,operation,route):
    e=mk(resource=resource,operation=operation,route=route);cap=rig.issue(e);obs=rig.gateway().observe(e)
    if stage=='precommit':
        with pytest.raises(RuntimeError):rig.sink().effectuate(cap,obs,fail_stage='before_commit')
        assert rig.effect_count()==0 and rig.state(e.nonce) is None
        assert rig.sink().effectuate(cap,obs)=='event:test-0001'
    elif stage=='ack-lost':
        with pytest.raises(AckLost):rig.sink().effectuate(cap,obs,fail_stage='after_commit_before_ack')
        assert rig.effect_count()==1
    else:
        assert rig.sink().effectuate(cap,obs)=='event:test-0001'
    with pytest.raises(Denied):rig.sink().effectuate(cap,obs)
    assert rig.effect_count()==1
    assert rig.spent('grant-1')==1
