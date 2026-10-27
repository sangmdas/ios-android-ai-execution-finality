from dataclasses import replace
import pytest
from dasfinality import ReferenceSystem, Effect

@pytest.fixture
def rig():
    s=ReferenceSystem(now=lambda:1000)
    s.create_grant(expires=2000, budget=100,
        resources=('file-A','file-B','vault-A','ledger-A','device-A'),
        operations=('WRITE','READ','SEND','PAY','ACTUATE'),
        routes=('api','ipc','socket','hardware'))
    yield s
    s.close()

@pytest.fixture
def mk():
    def build(**changes):
        data=dict(principal='user-1',tenant='tenant-A',resource='file-A',
            operation='WRITE',params={'body':'authorized'},sink_id='finality-sink-1',
            route='api',device='device-1',grant_id='grant-1',nonce='test-0001',cost=1)
        data.update(changes)
        return Effect(**data)
    return build
