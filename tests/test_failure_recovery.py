import pytest
from concurrent.futures import ThreadPoolExecutor
from dasfinality import Denied,AckLost,ReferenceSystem

def test_precommit_interruption_does_not_commit_effect_or_nonce(rig,mk):
    e=mk();cap=rig.issue(e)
    with pytest.raises(RuntimeError):rig.sink().effectuate(cap,rig.gateway().observe(e),fail_stage='before_commit')
    assert rig.effect_count()==0
    assert rig.state(e.nonce) is None
    assert rig.sink().effectuate(cap,rig.gateway().observe(e))

def test_lost_ack_does_not_authorize_duplicate_effect(rig,mk):
    e=mk();cap=rig.issue(e);obs=rig.gateway().observe(e)
    with pytest.raises(AckLost):rig.sink().effectuate(cap,obs,fail_stage='after_commit_before_ack')
    assert rig.effect_count()==1
    with pytest.raises(Denied):rig.sink().effectuate(cap,obs)
    assert rig.effect_count()==1

@pytest.mark.parametrize('parallel', [2,3,4,5,8,12,16,20])
def test_concurrent_replay_only_one_effect(rig,mk,parallel):
    e=mk();cap=rig.issue(e);obs=rig.gateway().observe(e)
    def f(_):
        try:return rig.sink().effectuate(cap,obs)
        except Denied:return None
    with ThreadPoolExecutor(max_workers=parallel) as pool: results=list(pool.map(f,range(parallel)))
    assert len([r for r in results if r])==1
    assert rig.effect_count()==1
    assert rig.spent('grant-1')==1

@pytest.mark.parametrize('parallel,budget', [(2,1),(3,1),(5,2),(8,3),(10,4),(15,5)])
def test_concurrent_distinct_nonce_cannot_overspend_budget(rig,mk,parallel,budget):
    rig.update_budget('grant-1',budget)
    prepared=[]
    for i in range(parallel):
        e=mk(nonce=f'parallel-{i}')
        cap=rig.issue(e)
        prepared.append((e,cap))
    def f(pair):
        e,cap=pair
        try:rig.sink().effectuate(cap,rig.gateway().observe(e));return True
        except Denied:return False
    with ThreadPoolExecutor(max_workers=parallel) as pool: results=list(pool.map(f,prepared))
    assert sum(results)==budget
    assert rig.effect_count()==budget
    assert rig.spent('grant-1')==budget

@pytest.mark.parametrize('different', ['nonce','params','resource','route','operation'])
def test_retry_of_materially_changed_operation_cannot_reuse_old_enablement(rig,mk,different):
    e=mk();cap=rig.issue(e)
    kwargs={'nonce':'other','params':{'body':'modified'},'resource':'file-B',
            'route':'socket','operation':'PAY'}
    with pytest.raises(Denied):rig.sink().effectuate(cap,rig.gateway().observe(mk(**{different:kwargs[different]})))
    assert rig.effect_count()==0

@pytest.mark.parametrize('costs,budget',[
 ([1,1,1],2), ([2,2,2],4), ([5,6,7],11),([3,4,8],7),([1,3,5,7],9)
])
def test_accounted_effects_bounded_with_prepared_offline_like_queue(rig,mk,costs,budget):
    rig.update_budget('grant-1',budget)
    q=[]
    for i,c in enumerate(costs):
        e=mk(nonce=f'queued-{i}',cost=c)
        try:q.append((e,rig.issue(e)))
        except Denied:pass
    accepted=0
    for e,cap in q:
        try:rig.sink().effectuate(cap,rig.gateway().observe(e)); accepted+=e.cost
        except Denied:pass
    assert rig.spent('grant-1')==accepted
    assert accepted<=budget

def test_restart_preserves_nonce_and_effect_in_persistent_sqlite(tmp_path,mk):
    path=str(tmp_path/'protected.db')
    key=b'authority-A'*3; gwkey=b'gateway-B'*4
    s=ReferenceSystem(db_path=path,now=lambda:1000,authority_key=key,gateway_key=gwkey)
    s.create_grant(expires=2000)
    e=mk();cap=s.issue(e);obs=s.gateway().observe(e)
    s.sink().effectuate(cap,obs);s.close()
    t=ReferenceSystem(db_path=path,now=lambda:1000,authority_key=key,gateway_key=gwkey)
    try:
        assert t.effect_count()==1
        with pytest.raises(Denied):t.sink().effectuate(cap,obs)
    finally:t.close()
