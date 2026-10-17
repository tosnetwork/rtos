"""An expired validator may recover as a full node, without regaining signing."""
import time

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
        lines=[line for line in text.splitlines() if self.session in line and any(reason in line for reason in reasons)]
        if not lines:raise RuntimeError('Expired full node lacks current-session signing admission refusal')
        if any('ValidatorGroup::on_generate_slot:' in line and 'Collation successful' in line for line in text.splitlines()):
            raise RuntimeError('Expired full node unexpectedly collated a new candidate')
        return lines[0]
