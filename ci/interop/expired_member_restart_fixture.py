"""An expired validator may recover as a full node, without regaining signing."""
import time
import re

from quorum_profile import check_committee_weights


class ExpiredFullNodeAcceptance:
    def __init__(self, member_id, restarted_at, minimum_wc, deadline, session):
        self.member_id=member_id;self.restarted_at=restarted_at;self.minimum_wc=minimum_wc
        self.deadline=deadline;self.session=session;self.started=None;self.samples=[]
        self.expected={member_id(i) for i in [0,2,4]}

    def observe(self, checked, voted, sample_directory):
        now=time.monotonic()
        if now>=self.deadline:raise TimeoutError('Expired full-node recovery exceeded the original recovery deadline')
        wc=checked['workchain_check']
        if checked['gen_utime']<=self.restarted_at or wc['gen_utime']<=self.restarted_at or wc['block']['seqno']<=self.minimum_wc:
            return False
        check_committee_weights(checked,{i:17 for i in [0,2,4,5]},self.member_id)
        if voted or checked['created_by'] not in self.expected or wc['created_by'] not in self.expected:
            raise RuntimeError('Expired member regained a vote or creator role')
        if not checked['verified_final_certificates'] or any(set(c['validator_ids'])!=self.expected or c['verified_weight']!=51 for c in checked['verified_final_certificates']):
            raise RuntimeError('Expired full-node recovery changed the authorized original quorum')
        if not wc['all_four_states_match_block_update'] or not wc['masterchain_anchor_checked']:
            raise RuntimeError('Expired full-node recovery lacks full anchored workchain states')
        if self.started is None:self.started=now
        self.samples.append({'block':checked['block'],'workchain':wc['block'],'sample_directory':str(sample_directory),
            'observed_at_unix':time.time(),'elapsed_seconds':now-self.started})
        first=self.samples[0]
        return len(self.samples)>=3 and now-self.started>=12 \
            and checked['block']['seqno']>first['block']['seqno'] and wc['block']['seqno']>first['workchain']['seqno']

    def refusal(self, text):
        reasons=['Isolated custody key differs from authenticated descriptor or has expired',
                 'Isolated successor schedule requires a future finite expiry']
        records=text.splitlines();lines=[]
        def scoped(line):
            return re.search(r'(?:^|\s)session_id='+re.escape(self.session)+r'(?=[\s:]|$)',line) is not None
        for index,line in enumerate(records):
            if not any(reason in line for reason in reasons):continue
            if scoped(line):lines.append(line)
            elif index>0 and line.startswith('Cannot start group: ') and '(construction drained=true); resetting session to Created for retry' in line:
                previous=records[index-1]
                if previous.startswith('SESSION_LIFECYCLE: reset_after_failure ') and scoped(previous):
                    lines.append(previous+'\n'+line)
        if not lines:raise RuntimeError('Expired full node lacks current-session signing admission refusal')
        if any('ValidatorGroup::on_generate_slot:' in line and 'Collation successful' in line for line in text.splitlines()):
            raise RuntimeError('Expired full node unexpectedly collated a new candidate')
        return lines[0]


class PendingIntentRecovery:
    """Observe pre-restart obligations; snapshots are never input to the node."""
    def __init__(self, namespaces, evidence, *, live=False):
        import hashlib
        import json
        from pathlib import Path
        self.namespaces=Path(namespaces);self.evidence=Path(evidence);self.records=[];self.completed_during_capture=[]
        self.evidence.mkdir(parents=True,exist_ok=False)
        for source in sorted(self.namespaces.glob('*/finality-intents/*.json')):
            if source.is_symlink() or source.parent.is_symlink() or source.parent.parent.is_symlink():
                raise RuntimeError('Pending intent snapshot requires an owned regular namespace')
            try:
                raw=source.read_bytes()
            except FileNotFoundError:
                if not live:raise
                proof=source.parent/'completed-v1'/source.with_suffix('.complete').name
                if source.exists() or proof.is_symlink() or proof.parent.is_symlink() or not proof.is_file():
                    raise RuntimeError('Live capture lost an intent without an exact completion record')
                proof_raw=proof.read_bytes();value=json.loads(proof_raw);record=value.get('record',{})
                expected=str(record.get('slot'))+'-'+str(record.get('candidate_hash'))+'.json'
                if value.get('schema')!=1 or source.name!=expected or not re.fullmatch(r'(0|[1-9][0-9]*)-[0-9a-f]{64}\.json',source.name):
                    raise RuntimeError('Live capture raced with a different completed candidate')
                self.completed_during_capture.append({'path':str(source.relative_to(self.namespaces)),
                    'completion_sha256':hashlib.sha256(proof_raw).hexdigest()})
                continue
            record=json.loads(raw)
            expected=str(record['slot'])+'-'+record['candidate_hash']+'.json'
            if source.name!=expected or not re.fullmatch(r'(0|[1-9][0-9]*)-[0-9a-f]{64}\.json',source.name):
                raise RuntimeError('Pending intent filename differs from its exact candidate')
            relative=source.relative_to(self.namespaces)
            saved=self.evidence/'before'/relative;saved.parent.mkdir(parents=True,exist_ok=True);saved.write_bytes(raw)
            self.records.append({'path':str(relative),'sha256':hashlib.sha256(raw).hexdigest(),'record':record})
        if not self.records:raise RuntimeError('No pre-restart pending intents were captured')
        self._write({'phase':'retained_before_restart','count':len(self.records),'records':self.records})

    def _write(self, value):
        import json
        (self.evidence/'receipt.json').write_text(json.dumps(value,indent=2)+'\n')

    def complete(self):
        import hashlib
        import json
        completed=[]
        for item in self.records:
            pending=self.namespaces/item['path']
            proof=pending.parent/'completed-v1'/pending.with_suffix('.complete').name
            if proof.is_symlink() or proof.parent.is_symlink():
                raise RuntimeError('Pending intent completion must be a regular owned record')
            if pending.exists() or not proof.exists():return False
            raw=proof.read_bytes();value=json.loads(raw)
            if value.get('schema')!=1 or value.get('record')!=item['record']:
                raise RuntimeError('Completed intent differs from the exact pre-restart record')
            saved=self.evidence/'completed'/proof.relative_to(self.namespaces)
            saved.parent.mkdir(parents=True,exist_ok=True);saved.write_bytes(raw)
            completed.append({'path':str(proof.relative_to(self.namespaces)),'sha256':hashlib.sha256(raw).hexdigest()})
        self._write({'phase':'all_original_intents_completed','count':len(self.records),'records':self.records,'completed':completed})
        return True


def validate_followup_frontier(args):
    if getattr(args, 'followup_intent_frontier', False) and not (
        getattr(args, 'expired_member_restart', False)
        and getattr(args, 'source_ack_partition_restart', False)
    ):
        raise RuntimeError('Follow-up frontier requires the explicit expired-member original ACK restart')


class LiveIntentFrontier(PendingIntentRecovery):
    """A separate live frontier after original recovery; never extends that budget."""
    def __init__(self, namespaces, evidence):
        self.started=time.monotonic();self.started_unix=time.time()
        self.deadline=self.started+180
        super().__init__(namespaces,evidence,live=True)

    def _write(self, value):
        elapsed=time.monotonic()-self.started
        if elapsed>=180:
            raise TimeoutError('Follow-up captured intents exceeded their separate 180-second budget')
        value={**value,'phase':{'retained_before_restart':'followup_frontier_captured',
            'all_original_intents_completed':'followup_frontier_completed'}[value['phase']],
            'separate_budget_seconds':180,'budget_started_at_unix':self.started_unix,
            'elapsed_seconds':elapsed,'original_recovery_budget_extended':False,
            'completed_during_capture':self.completed_during_capture}
        super()._write(value)

    def complete(self):
        if time.monotonic()>=self.deadline:
            raise TimeoutError('Follow-up captured intents exceeded their separate 180-second budget')
        return super().complete()
