from dataclasses import replace,asdict
import pytest
from dasfinality import Effect, Denied, InvalidMessage
from dasfinality.model import canonical,digest

@pytest.mark.parametrize('operation,resource,route,cost',[
    ('WRITE','file-A','api',1), ('READ','file-B','ipc',1),
    ('SEND','vault-A','socket',2), ('PAY','ledger-A','api',4),
    ('ACTUATE','device-A','hardware',2),
    ('WRITE','file-B','ipc',0),('READ','file-A','socket',1),
    ('SEND','file-B','api',3),('PAY','vault-A','ipc',7),
    ('ACTUATE','ledger-A','socket',6),('WRITE','vault-A','hardware',5),
    ('READ','ledger-A','api',1),('SEND','device-A','ipc',2),
    ('PAY','file-A','hardware',3),('ACTUATE','file-B','api',4),
    ('WRITE','device-A','socket',5),('READ','vault-A','hardware',6),
    ('SEND','ledger-A','hardware',2),('PAY','device-A','socket',1),
    ('ACTUATE','vault-A','ipc',1),
])
def test_valid_operation_variants(rig,mk,operation,resource,route,cost):
    e=mk(operation=operation,resource=resource,route=route,cost=cost)
    enablement=rig.issue(e)
    event=rig.sink().effectuate(enablement,rig.gateway().observe(e))
    assert event=='event:test-0001'
    assert rig.spent('grant-1')==cost
    assert rig.effect_count()==1
    assert rig.state(e.nonce)['status']=='EFFECTUATED'

@pytest.mark.parametrize('changes',[
    {'principal':'intruder'}, {'tenant':'other-tenant'},{'resource':'unlisted'},
    {'operation':'ERASE'},{'route':'direct'},{'sink_id':'other-sink'},
    {'device':'old-device'},{'grant_id':'missing'},
    {'cost':101},{'resource':'private-key'},{'operation':'ROOT'},
    {'route':'browser-bypass'},{'principal':'agent-2'},
    {'tenant':'tenant-B'},{'resource':'file-C'},
    {'operation':'DECRYPT'},{'route':'bluetooth'},
    {'sink_id':'attacker-sink'},{'device':'cloned-device'},
    {'cost':999999},
])
def test_invalid_upstream_authority_never_issues(rig,mk,changes):
    e=mk(**changes)
    with pytest.raises(Denied):rig.issue(e)
    assert rig.effect_count()==0

@pytest.mark.parametrize('changes',[
    {'principal':'user-2'},{'tenant':'tenant-B'},{'resource':'file-B'},
    {'operation':'PAY'},{'route':'socket'},{'sink_id':'sink-B'},
    {'device':'device-B'},{'grant_id':'grant-other'},{'nonce':'different'},
    {'cost':2},{'params':{'body':'tampered'}},{'params':{}},
    {'params':{'body':'authorized','extra':1}},
    {'params':{'body':'authorized','recipient':'attacker'}},
    {'resource':'vault-A'},{'operation':'SEND'},{'route':'hardware'},
    {'params':{'body':['authorized']}},
])
def test_actual_effect_mismatch_burns_authorized_nonce(rig,mk,changes):
    e=mk(); permit=rig.issue(e)
    actual=mk(**changes)
    with pytest.raises(Denied):rig.sink().effectuate(permit,rig.gateway().observe(actual))
    assert rig.state(e.nonce)['status']=='DENIED'
    assert rig.effect_count()==0
    with pytest.raises(Denied):rig.sink().effectuate(permit,rig.gateway().observe(e))

@pytest.mark.parametrize('changes',[
    {'digest':'a'*64},{'grant_id':'bad-grant'},{'grant_generation':999},
    {'owner_epoch':999},{'policy_generation':999},{'expiry':5000},
    {'sink_id':'bad-sink'},{'nonce':'malicious-replacement'},
    {'predecessor_receipt':'receipt:fake'},{'signature':'00'*32},
])
def test_unauthenticated_capability_modification_cannot_burn(rig,mk,changes):
    e=mk(); permit=rig.issue(e)
    fake=replace(permit,**changes)
    with pytest.raises(InvalidMessage):rig.sink().effectuate(fake,rig.gateway().observe(e))
    assert rig.state(e.nonce) is None
    assert rig.sink().effectuate(permit,rig.gateway().observe(e))=='event:test-0001'

@pytest.mark.parametrize('changes',[
    {'gateway_id':'malicious-gateway'},{'signature':'not-valid'},
])
def test_forged_gateway_evidence_does_not_burn(rig,mk,changes):
    e=mk();permit=rig.issue(e); observation=rig.gateway().observe(e)
    forged=replace(observation,**changes)
    with pytest.raises(InvalidMessage):rig.sink().effectuate(permit,forged)
    assert rig.state(e.nonce) is None

@pytest.mark.parametrize('invalid',[
    {'body':float('nan')},{'body':float('inf')},{'cost':1.0},
    {'body':set([1])},{'body':b'abc'},{'body':{'outer':object()}},
])
def test_invalid_json_effect_values_rejected(mk,invalid):
    with pytest.raises(InvalidMessage):mk(params=invalid)

@pytest.mark.parametrize('a,b,expected',[
    ({'x':1,'y':2},{'y':2,'x':1},True),
    ({'x':[1,2]},{'x':[2,1]},False),
    ({'x':'abc'},{'x':'ABC'},False),
    ({'x':0},{'x':1},False),
    ({'x':True},{'x':1},False),
    ({'x':None},{},False),
])
def test_canonical_payload_comparison(a,b,expected):
    assert (digest(a)==digest(b)) is expected

def test_input_params_mutation_cannot_change_issued_digest(mk):
    payload={'body':['x']}
    e=mk(params=payload)
    before=e.effect_digest
    payload['body'].append('new')
    assert e.effect_digest==before

def test_replayed_event_does_not_duplicate(rig,mk):
    e=mk();cap=rig.issue(e);o=rig.gateway().observe(e)
    rig.sink().effectuate(cap,o)
    with pytest.raises(Denied):rig.sink().effectuate(cap,o)
    assert rig.effect_count()==1
