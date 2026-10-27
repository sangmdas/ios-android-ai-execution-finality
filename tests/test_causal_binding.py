import pytest
from dasfinality import Denied,InvalidMessage

def test_dependency_requires_receipt_even_with_valid_original_approval(rig,mk):
    pred=mk(nonce='pred-1')
    succ=mk(nonce='succ-1',requires_effect_digest=pred.effect_digest)
    with pytest.raises(Denied, match='predecessor'):rig.issue(succ)

def test_receipt_must_match_exact_predecessor_effect(rig,mk):
    pred=mk(nonce='pred-1')
    evt=rig.sink().effectuate(rig.issue(pred),rig.gateway().observe(pred))
    receipt=rig.receipt(evt)
    other=mk(nonce='not-that-pred')
    succ=mk(nonce='succ-1',requires_effect_digest=other.effect_digest)
    with pytest.raises(Denied,match='different predecessor'):rig.issue(succ,predecessor_receipt=receipt)

def test_matching_real_local_predecessor_receipt_validates_successor(rig,mk):
    pred=mk(nonce='pred-1')
    evt=rig.sink().effectuate(rig.issue(pred),rig.gateway().observe(pred))
    receipt=rig.receipt(evt)
    succ=mk(nonce='succ-1',requires_effect_digest=pred.effect_digest)
    cap=rig.issue(succ,predecessor_receipt=receipt)
    assert rig.sink().effectuate(cap,rig.gateway().observe(succ))=='event:succ-1'

@pytest.mark.parametrize('value',['bad',123,'z'*64,'f'*63,'F'*64,''])
def test_invalid_predecessor_digest_syntax_refused(mk,value):
    with pytest.raises(InvalidMessage):mk(requires_effect_digest=value)

@pytest.mark.parametrize('field', ['resource','operation','params','principal'])
def test_receipt_cannot_be_reused_to_authorize_a_different_predecessor(rig,mk,field):
    pred=mk(nonce='pred-1')
    event=rig.sink().effectuate(rig.issue(pred),rig.gateway().observe(pred))
    receipt=rig.receipt(event)
    alternatives={'resource':'file-B','operation':'SEND','params':{'body':'other'},'principal':'user-2'}
    wrong=mk(nonce='pred-1',**{field:alternatives[field]})
    succ=mk(nonce='succ-1',requires_effect_digest=wrong.effect_digest)
    with pytest.raises(Denied):rig.issue(succ,predecessor_receipt=receipt)
