from dataclasses import replace
import pytest
from dasfinality import Denied,InvalidMessage

@pytest.mark.parametrize('transition',[
 'revoke','rotate_grant','change_policy','transfer_owner','update_budget'
])
def test_prepared_permission_invalidated_by_authoritative_change(rig,mk,transition):
    e=mk();cap=rig.issue(e)
    if transition=='change_policy':rig.change_policy()
    elif transition=='transfer_owner':rig.transfer_owner('grant-1','device-new')
    elif transition=='update_budget':rig.update_budget('grant-1',50)
    else:getattr(rig,transition)('grant-1')
    with pytest.raises(Denied):rig.sink().effectuate(cap,rig.gateway().observe(e))
    assert rig.state(e.nonce)['status']=='DENIED'

@pytest.mark.parametrize('ttl',[-1,0,1.25,None,'20'])
def test_invalid_ttl(rig,mk,ttl):
    with pytest.raises((InvalidMessage,TypeError)):rig.issue(mk(),ttl=ttl)

@pytest.mark.parametrize('ttl,offset,authorized',[
  (1,0,True),(1,1,False),(20,19,True),(20,20,False),
  (120,119,True),(120,120,False),(1000,999,True),(1000,1000,False),
])
def test_expiry_boundary(rig,mk,ttl,offset,authorized):
    clock=[1000];rig.now=lambda:clock[0]
    e=mk();cap=rig.issue(e,ttl=ttl);clock[0]=1000+offset
    if authorized:assert rig.sink().effectuate(cap,rig.gateway().observe(e))
    else:
        with pytest.raises(Denied):rig.sink().effectuate(cap,rig.gateway().observe(e))

@pytest.mark.parametrize('budget,cost,permitted',[
 (0,0,True),(0,1,False),(1,1,True),(1,2,False),(3,3,True),
 (3,4,False),(10,10,True),(10,11,False),(99,99,True),(99,100,False)
])
def test_single_effect_budget_boundary(rig,mk,budget,cost,permitted):
    rig.update_budget('grant-1',budget)
    e=mk(cost=cost)
    if not permitted:
        with pytest.raises(Denied):rig.issue(e)
    else:
        cap=rig.issue(e);rig.sink().effectuate(cap,rig.gateway().observe(e))
        assert rig.spent('grant-1')==cost

@pytest.mark.parametrize('sequence',[
  (1,1,1),(1,2,1),(5,5,1),(10,20,30),(0,0,100),(3,3,4),
  (25,25,25),(33,33,34)
])
def test_sequential_quota_accounting(rig,mk,sequence):
    rig.update_budget('grant-1',100)
    for i,cost in enumerate(sequence):
        e=mk(nonce=f'quota-{i}',cost=cost)
        cap=rig.issue(e)
        rig.sink().effectuate(cap,rig.gateway().observe(e))
    assert rig.spent('grant-1')==sum(sequence)
    assert rig.effect_count()==len(sequence)

def test_protected_denial_does_not_charge_quota(rig,mk):
    e=mk(cost=15);cap=rig.issue(e)
    with pytest.raises(Denied):rig.sink().effectuate(cap,rig.gateway().observe(mk(params={'new':'effect'})))
    assert rig.spent('grant-1')==0

def test_grant_generation_rotation_allows_fresh_request(rig,mk):
    old=mk(nonce='old-1'); oldcap=rig.issue(old)
    rig.rotate_grant('grant-1')
    with pytest.raises(Denied):rig.sink().effectuate(oldcap,rig.gateway().observe(old))
    new=mk(nonce='new-1');cap=rig.issue(new)
    assert rig.sink().effectuate(cap,rig.gateway().observe(new))

def test_owner_transfer_fences_stale_device_and_enables_new_owner(rig,mk):
    old=mk(nonce='old-device');cap=rig.issue(old)
    rig.transfer_owner('grant-1','device-2')
    with pytest.raises(Denied):rig.sink().effectuate(cap,rig.gateway().observe(old))
    new=mk(nonce='new-device',device='device-2')
    assert rig.sink().effectuate(rig.issue(new),rig.gateway().observe(new))
