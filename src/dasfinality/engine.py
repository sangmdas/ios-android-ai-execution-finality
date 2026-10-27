"""Reference simulation of protected authority, sink-local state, and causal-effect receipts.

Security boundaries are ASSUMED, not realized by process/kernel/hardware isolation.
For remote side effects, the mock SQLite effect row is NOT a substitute for an
external transaction's independently attested real-world completion.
"""
from __future__ import annotations
import sqlite3, threading, time, secrets, json
from dataclasses import asdict
from .model import Effect,Enablement,ObservedOperation,Denied,InvalidMessage,AckLost,mac,secure_equal

DDL = '''
CREATE TABLE IF NOT EXISTS grants (
 id TEXT PRIMARY KEY, principal TEXT NOT NULL, tenant TEXT NOT NULL,
 resources TEXT NOT NULL, operations TEXT NOT NULL, routes TEXT NOT NULL,
 sink_id TEXT NOT NULL, owner TEXT NOT NULL, owner_epoch INTEGER NOT NULL,
 generation INTEGER NOT NULL, active INTEGER NOT NULL,
 expires INTEGER NOT NULL, budget INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS control (id INTEGER PRIMARY KEY CHECK(id=1),policy_generation INTEGER NOT NULL);
INSERT OR IGNORE INTO control(id,policy_generation) VALUES(1,1);
CREATE TABLE IF NOT EXISTS consumptions (
 nonce TEXT PRIMARY KEY, effect_digest TEXT NOT NULL,
 status TEXT NOT NULL, reason TEXT, event_id TEXT
);
CREATE TABLE IF NOT EXISTS effects (
 event_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE,
 effect_digest TEXT NOT NULL, resource TEXT NOT NULL, operation TEXT NOT NULL,
 effect_json TEXT NOT NULL, committed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
 receipt_id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
 accepted INTEGER NOT NULL, validator_id TEXT NOT NULL
);
'''

class ReferenceSystem:
    """Single-process reference harness, with durable SQLite state and independent keys."""
    def __init__(self, db_path=':memory:', now=None, authority_key=None, gateway_key=None):
        self.connection=sqlite3.connect(db_path,isolation_level=None,check_same_thread=False)
        self.connection.row_factory=sqlite3.Row
        self.connection.executescript(DDL)
        self.lock=threading.RLock()
        self.now=now or (lambda:int(time.time()))
        self.authority_key=authority_key or secrets.token_bytes(32)
        self.gateway_key=gateway_key or secrets.token_bytes(32)
        self.gateway_id='protected-gateway'
        self.allowed_sink='finality-sink-1'
    def close(self):self.connection.close()
    def _grant(self, grant_id):
        row=self.connection.execute('SELECT * FROM grants WHERE id=?',(grant_id,)).fetchone()
        if not row:raise Denied('unknown grant')
        return row
    def _generation(self):
        return self.connection.execute('SELECT policy_generation FROM control WHERE id=1').fetchone()[0]
    def create_grant(self, *,grant_id='grant-1',principal='user-1',tenant='tenant-A',resources=('file-A',),
                     operations=('WRITE',),routes=('api',),sink_id='finality-sink-1',owner='device-1',
                     expires=9999999999,budget=100):
        with self.lock:
            self.connection.execute('''INSERT INTO grants
            (id,principal,tenant,resources,operations,routes,sink_id,owner,owner_epoch,
            generation,active,expires,budget,spent)
            VALUES(?,?,?,?,?,?,?,?,1,1,1,?,?,0)''',
            (grant_id,principal,tenant,json.dumps(list(resources)),json.dumps(list(operations)),
             json.dumps(list(routes)),sink_id,owner,expires,budget))
    def _check_grant(self,grant,effect, now):
        if not grant['active']:raise Denied('revoked')
        if now>=grant['expires']:raise Denied('expired grant')
        if effect.grant_id!=grant['id'] or effect.principal!=grant['principal'] or effect.tenant!=grant['tenant']:
            raise Denied('wrong source/tenant')
        if effect.resource not in json.loads(grant['resources']):raise Denied('resource not authorized')
        if effect.operation not in json.loads(grant['operations']):raise Denied('operation not authorized')
        if effect.route not in json.loads(grant['routes']):raise Denied('route not authorized')
        if effect.sink_id!=grant['sink_id']:raise Denied('wrong sink')
        if effect.device!=grant['owner']:raise Denied('stale owner')
        if grant['spent']+effect.cost>grant['budget']:raise Denied('quota exceeded')
    def issue(self,effect:Effect,ttl=120,predecessor_receipt=None):
        """Operation-bound preparation. It does not cause a consequential effect."""
        if not isinstance(ttl,int) or ttl<=0:raise InvalidMessage('positive integer TTL required')
        with self.lock:
            now=self.now();grant=self._grant(effect.grant_id)
            self._check_grant(grant,effect,now)
            if effect.requires_effect_digest and not predecessor_receipt:
                raise Denied('missing required predecessor effect receipt')
            if predecessor_receipt is not None:
                self._check_receipt(predecessor_receipt,effect.requires_effect_digest)
            claims=dict(digest=effect.effect_digest, grant_id=effect.grant_id,
              grant_generation=grant['generation'],owner_epoch=grant['owner_epoch'],
              policy_generation=self._generation(),expiry=min(now+ttl,grant['expires']),
              sink_id=effect.sink_id,nonce=effect.nonce,predecessor_receipt=predecessor_receipt)
            return Enablement(**claims,signature=mac(self.authority_key,claims))
    def gateway(self):return Gateway(self)
    def sink(self):return FinalitySink(self)
    def revoke(self,grant_id):
        with self.lock:
            self.connection.execute('UPDATE grants SET active=0,generation=generation+1 WHERE id=?',(grant_id,))
    def rotate_grant(self,grant_id):
        with self.lock:
            self.connection.execute('UPDATE grants SET generation=generation+1 WHERE id=?',(grant_id,))
    def change_policy(self):
        with self.lock:
            self.connection.execute('UPDATE control SET policy_generation=policy_generation+1 WHERE id=1')
    def transfer_owner(self,grant_id,new_owner):
        with self.lock:
            self.connection.execute('''UPDATE grants SET owner=?,owner_epoch=owner_epoch+1,
            generation=generation+1 WHERE id=?''',(new_owner,grant_id))
    def update_budget(self,grant_id,new_budget):
        with self.lock:
            self.connection.execute('UPDATE grants SET budget=?,generation=generation+1 WHERE id=?',(new_budget,grant_id))
    def state(self,nonce):
        row=self.connection.execute('SELECT status,reason,event_id FROM consumptions WHERE nonce=?',(nonce,)).fetchone()
        return dict(row) if row else None
    def spent(self,grant_id):return self._grant(grant_id)['spent']
    def effect_count(self):return self.connection.execute('SELECT COUNT(*) FROM effects').fetchone()[0]
    def receipt(self,event_id,validator_id='local-result-verifier'):
        """Accept independently recorded LOCAL mock-effect outcome, not a remote completion claim."""
        with self.lock:
            row=self.connection.execute('SELECT event_id FROM effects WHERE event_id=?',(event_id,)).fetchone()
            if not row:raise Denied('no observed committed effect')
            receipt_id='receipt:'+event_id
            self.connection.execute('INSERT OR IGNORE INTO receipts VALUES(?,?,1,?)',(receipt_id,event_id,validator_id))
            return receipt_id
    def _check_receipt(self,receipt_id,required_digest=None):
        rec=self.connection.execute('''SELECT e.effect_digest FROM receipts r
                  JOIN effects e ON r.event_id=e.event_id
                  WHERE r.receipt_id=? AND r.accepted=1''',(receipt_id,)).fetchone()
        if not rec:raise Denied('unaccepted receipt or absent proven local effect')
        if required_digest is not None and rec['effect_digest']!=required_digest:
            raise Denied('receipt proves a different predecessor effect')
        return True

class Gateway:
    """Models a trusted observation adapter; the key is protected by assumption only."""
    def __init__(self,system):self.s=system
    def observe(self,effect:Effect):
        claims={'effect':asdict(effect),'gateway_id':self.s.gateway_id}
        return ObservedOperation(effect=effect,gateway_id=self.s.gateway_id,
                                 signature=mac(self.s.gateway_key,claims))

class FinalitySink:
    """Checks independently observed operation and commits mock effect atomically with nonce."""
    def __init__(self,system):self.s=system
    def effectuate(self,enablement:Enablement,observation:ObservedOperation,*,fail_stage=None):
        s=self.s
        if not isinstance(enablement,Enablement) or not isinstance(observation,ObservedOperation):
            raise InvalidMessage('typed evidence required')
        # Authenticate before attempting to burn a nonce. Forged records cannot poison state.
        if not secure_equal(enablement.signature,mac(s.authority_key,enablement.claims())):
            raise InvalidMessage('invalid protected enablement')
        if observation.gateway_id!=s.gateway_id or not secure_equal(
                observation.signature,mac(s.gateway_key,observation.claims())):
            raise InvalidMessage('invalid gateway evidence')
        with s.lock:
            db=s.connection;db.execute('BEGIN IMMEDIATE')
            rejected=None;event_id=None
            try:
                nonce=enablement.nonce
                if db.execute('SELECT 1 FROM consumptions WHERE nonce=?',(nonce,)).fetchone():
                    raise Denied('single-use nonce already consumed or refused')
                actual=observation.effect
                try:
                    if actual.nonce!=nonce or actual.effect_digest!=enablement.digest:
                        raise Denied('actual operation differs')
                    if enablement.sink_id!=actual.sink_id or actual.sink_id!=s.allowed_sink:
                        raise Denied('sink mismatch')
                    if s.now()>=enablement.expiry:raise Denied('enablement expired')
                    if s._generation()!=enablement.policy_generation:raise Denied('stale policy')
                    g=s._grant(enablement.grant_id)
                    if g['generation']!=enablement.grant_generation or g['owner_epoch']!=enablement.owner_epoch:
                        raise Denied('stale authority epoch')
                    s._check_grant(g,actual,s.now())
                    if actual.requires_effect_digest and not enablement.predecessor_receipt:
                        raise Denied('mandatory predecessor receipt absent')
                    if enablement.predecessor_receipt:
                        s._check_receipt(enablement.predecessor_receipt,actual.requires_effect_digest)
                    if fail_stage=='before_commit':raise RuntimeError('simulated precommit interruption')
                    event_id='event:'+nonce
                    db.execute('INSERT INTO consumptions VALUES(?,?,?,?,?)',
                              (nonce,actual.effect_digest,'EFFECTUATED',None,event_id))
                    db.execute('INSERT INTO effects VALUES(?,?,?,?,?,?,?)',
                              (event_id,nonce,actual.effect_digest,actual.resource,actual.operation,
                               json.dumps(asdict(actual),sort_keys=True),s.now()))
                    db.execute('UPDATE grants SET spent=spent+? WHERE id=?',(actual.cost,actual.grant_id))
                except Denied as exc:
                    rejected=str(exc)
                    # A properly authenticated but refused operation burns the scoped nonce.
                    db.execute('INSERT INTO consumptions VALUES(?,?,?,?,?)',
                              (nonce,enablement.digest,'DENIED',rejected,None))
                db.execute('COMMIT')
            except Exception:
                db.execute('ROLLBACK')
                raise
            if rejected:raise Denied(rejected)
            if fail_stage=='after_commit_before_ack':raise AckLost('committed locally, acknowledgment lost')
            return event_id
