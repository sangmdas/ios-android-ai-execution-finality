from dasfinality import ReferenceSystem,Effect,Denied
s=ReferenceSystem(now=lambda:1000)
s.create_grant(expires=2000)
gateway=s.gateway()
e=Effect(principal='user-1',tenant='tenant-A',resource='file-A',operation='WRITE',
         params={'content':'approved content'},sink_id='finality-sink-1',route='api',
         device='device-1',grant_id='grant-1',nonce='demo-001',cost=1)
permit=s.issue(e)
event=s.sink().effectuate(permit,gateway.observe(e))
print('COMMITTED:',event,'spent:',s.spent('grant-1'))
try:s.sink().effectuate(permit,gateway.observe(e))
except Denied as exc:print('REPLAY REFUSED:',exc)
receipt=s.receipt(event)
print('ACCEPTED MOCK-EFFECT RECEIPT:',receipt)
