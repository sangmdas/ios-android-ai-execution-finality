import pytest
from dasfinality import Denied

def test_receipt_only_for_committed_mock_effect(rig):
    with pytest.raises(Denied):rig.receipt('event:not-real')

@pytest.mark.parametrize('bad_receipt',[
 'receipt:missing','receipt:event:not-issued','receipt:fake','success',
 'receipt:event:queued','receipt:event:timeout','receipt:event:incorrect-target',
 'receipt:event:cross-tenant'
])
def test_unaccepted_receipt_cannot_issue_successor(rig,mk,bad_receipt):
    with pytest.raises(Denied):rig.issue(mk(nonce='successor-1'),predecessor_receipt=bad_receipt)

@pytest.mark.parametrize('successor_operation,resource',[
 ('WRITE','file-B'),('PAY','ledger-A'),('SEND','vault-A'),
 ('READ','file-A'),('ACTUATE','device-A')
])
def test_verified_predecessor_receipt_allows_separately_authorized_successor(rig,mk,successor_operation,resource):
    prev=mk(nonce='predecessor')
    event=rig.sink().effectuate(rig.issue(prev),rig.gateway().observe(prev))
    receipt=rig.receipt(event)
    nextact=mk(operation=successor_operation,resource=resource,nonce='successor')
    cap=rig.issue(nextact,predecessor_receipt=receipt)
    assert rig.sink().effectuate(cap,rig.gateway().observe(nextact))

@pytest.mark.parametrize('changes',[
 {'principal':'attacker'}, {'resource':'other'}, {'operation':'DELETE'},
 {'tenant':'other'}, {'route':'bypass'}
])
def test_receipt_does_not_expand_source_authority(rig,mk,changes):
    p=mk(nonce='p');event=rig.sink().effectuate(rig.issue(p),rig.gateway().observe(p))
    receipt=rig.receipt(event)
    with pytest.raises(Denied):rig.issue(mk(nonce='s',**changes),predecessor_receipt=receipt)

@pytest.mark.parametrize('tampered',[
 'receipt:event:predecessor-2','receipt:event:predecessor:success',
 'receipt:event:predecessor:rollback','receipt:event:predecessor:revoked'
])
def test_receipt_identifier_substitution_denied(rig,mk,tampered):
    p=mk(nonce='predecessor'); event=rig.sink().effectuate(rig.issue(p),rig.gateway().observe(p))
    rig.receipt(event)
    with pytest.raises(Denied):rig.issue(mk(nonce='successor'),predecessor_receipt=tampered)

@pytest.mark.parametrize('transition', ['revoke','rotate_grant','change_policy','transfer_owner'])
def test_predecessor_receipt_never_overrides_fresh_authority(rig,mk,transition):
    p=mk(nonce='predecessor');event=rig.sink().effectuate(rig.issue(p),rig.gateway().observe(p))
    receipt=rig.receipt(event)
    n=mk(nonce='successor');cap=rig.issue(n,predecessor_receipt=receipt)
    if transition=='change_policy':rig.change_policy()
    elif transition=='transfer_owner':rig.transfer_owner('grant-1','new-owner')
    else:getattr(rig,transition)('grant-1')
    with pytest.raises(Denied):rig.sink().effectuate(cap,rig.gateway().observe(n))
