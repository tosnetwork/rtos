"""Natural custody expiry on one owned active peer, sharing the restart budget."""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import re
import time

from mixed_matrix import child_checked, cpp_block, cpp_certificate, digest, identity, native_state, rpc, write
from quorum_profile import check_committee_weights


def expiry_plan(profile, args):
    member = getattr(args, 'signer_expiry_member', None)
    passive = getattr(args, 'expired_member_restart', False)
    if member is None:
        if passive:raise ValueError('Expired member restart requires its explicit finite expiry')
        return None
    if passive:
        if member != 5 or args.interrupt_rust_member != 5 or not args.source_ack_partition_restart \
                or args.recovery_below_quorum or args.source_ack_fault not in ['sync-eio','write-enospc']:
            raise ValueError('Expired member restart requires member5 ACK/partition restart with surviving quorum')
    elif member != 5 or args.interrupt_rust_member != 2 or not args.source_ack_partition_restart \
            or not args.recovery_below_quorum or args.source_ack_fault != 'sync-eio':
        raise ValueError('Signer expiry requires the declared member5 plus member2 ACK/partition restart combination')
    if any(profile.get(k) for k in ['weighted_quorum_pause','initial_probe_pause','observer_budget']):
        raise ValueError('Signer expiry requires its separate declared availability case')
    from quorum_profile import epoch_weights
    if epoch_weights(profile,'successor_weights',[0,2,4,5]) != {i:17 for i in [0,2,4,5]}:
        raise ValueError('Signer expiry combination requires the original equal-weight committee')
    return {'member':5, 'expire_at':profile['genesis_time']+profile['activation_delay']+50,
        'interrupted_member':5 if passive else 2, 'quorum_weight':46, 'total_weight':68,
        'surviving_weight_during_interruption':51 if passive else 34, 'surviving_weight_after_restart':51}


class SignerExpiry:
    def __init__(self,args,root,node,checkpoint):
        self.args=args;self.root=root;self.node=node
        self.directory=root/'signer-expiry';self.directory.mkdir()
        self.started=time.monotonic();self.deadline=self.started+args.recovery_timeout
        self.started_unix=time.time();self.plan=args.signer_expiry_plan
        if self.started_unix>=self.plan['expire_at']:
            raise RuntimeError('Signer expiry must be observed from a live pre-expiry session')
        session=base64.b64decode(checkpoint['verified_final_certificates'][0]['session_id'],validate=True).hex()
        candidates=[]
        for path in (node['directory']/'node_db/catchains/consensus/v2').glob('*/session-runtime.json'):
            value=json.loads(path.read_text())
            if value['session']==session and value['shard_workchain']==-1 and value['role']=='validator':candidates.append(path)
        if len(candidates)!=1:raise RuntimeError('Signer expiry needs the exact current active MC runtime')
        runtime=candidates[0];profile=runtime.with_name('isolated-signing.json')
        value=json.loads(profile.read_text());schedule=profile.parent.parent/'isolated-signing-schedule.json'
        if value['validator']!=hashlib.sha256(b'n6-validator-id-5').hexdigest() or value['session']!=session:
            raise RuntimeError('Expiry profile differs from the selected member/session')
        if value['expire_at']!=self.plan['expire_at'] or json.loads(schedule.read_text())['expire_at']!=value['expire_at']:
            raise RuntimeError('Signer expiry was not provisioned in the original profile and successor schedule')
        self.bindings={str(p):digest(p) for p in [profile,schedule,node['directory']/'validator-prepared.json']}
        self.session=session;self.pid=node['process'].pid;self.ticks=node['start_ticks']
        self.log=node['directory']/'node.log';self.offset=self.log.stat().st_size
        (self.directory/'selected-runtime.json').write_bytes(runtime.read_bytes())
        (self.directory/'original-profile.json').write_bytes(profile.read_bytes())
        # Contains only public authority metadata and local paths, never key bytes.
        (self.directory/'original-schedule.json').write_bytes(schedule.read_bytes())
        self.receipt={'phase':'waiting_for_natural_expiry','plan':self.plan,'session':session,
            'pid':self.pid,'start_ticks':self.ticks,'budget_started_at_unix':self.started_unix,
            'recovery_limit_seconds':args.recovery_timeout,'authority_file_hashes':self.bindings,
            'manual_database_repair':False,'clock_adjusted':False,'log_offset':self.offset}
        self.save()

    def alive(self):
        if self.node['process'].returncode is not None or Path(f'/proc/{self.pid}/stat').read_text().split()[21]!=self.ticks:
            raise RuntimeError('Expiring peer changed or exited')
        if any(digest(Path(p))!=h for p,h in self.bindings.items()):raise RuntimeError('Signer expiry authority changed')
        if time.monotonic()>=self.deadline:raise TimeoutError('Signer expiry exceeded the original recovery deadline')

    def save(self):
        self.receipt['elapsed_seconds']=time.monotonic()-self.started
        write(self.directory/'receipt.json',self.receipt)

    async def qualify(self,args,nodes,endpoints,lite_configs,zero,governing,checkpoint,member_id):
        while True:
            self.alive()
            with self.log.open('rb') as stream:stream.seek(self.offset);text=stream.read().decode(errors='replace')
            expiry=next((l for l in text.splitlines() if 'signing generation expired and retired' in l),None)
            refusal=re.search(r'^Session '+self.session+r' broadcast_vote: failed to sign vote: (?:signing generation expired and retired|signing journal stopped/retired)$',text,re.M)
            if time.time()>=self.plan['expire_at'] and expiry and refusal:
                self.receipt.update(phase='refusal_observed',observed_at_unix=time.time(),expiry_line=expiry,refusal_line=refusal.group(0));self.save();break
            await asyncio.sleep(min(.1,max(0,self.deadline-time.monotonic())))
        histories=[{} for _ in nodes];floor=checkpoint['block']['seqno']
        while True:
            self.alive()
            replies=await asyncio.wait_for(asyncio.gather(*(asyncio.to_thread(rpc,url,'getMasterchainInfo') for url in endpoints)),self.deadline-time.monotonic())
            for i,info in enumerate(replies):
                if identity(info['init'])!=identity(zero):raise RuntimeError('Expiry witness endpoint changed Genesis')
                histories[i][identity(info['last'])]=info
                if len(histories[i])>512:del histories[i][next(iter(histories[i]))]
            common=set.intersection(*(set(h) for h in histories));keys=[k for k in common if k[2]>floor]
            if not keys:await asyncio.sleep(.2);continue
            key=max(keys,key=lambda k:k[2]);floor=key[2];infos={i:h[key] for i,h in enumerate(histories)}
            if len({x['state_root_hash'] for x in infos.values()})!=1:raise RuntimeError('Expiry witness applied states disagree')
            target=self.directory/f'expired-{floor}';target.mkdir();block=infos[0]['last']
            proof=await cpp_certificate(args.snapshot,nodes[0],zero,block,target)
            sample={'zerostate':zero,'reference':infos[0],'comparison':infos[2],
                'all_references':infos,'block':await cpp_block(args.snapshot,nodes[0],block,target),
                'masterchain_state':await native_state(args.snapshot,lite_configs[0],'cpp-0',block,target/'mc-state'),
                'certificates':[proof],'governing_key_block':{**governing,'certificates':[proof]}}
            write(target/'sample.json',sample)
            await child_checked([args.block_checker,target/'sample.json',target/'checked.json'],target/'checker.log')
            checked=json.loads((target/'checked.json').read_text())
            check_committee_weights(checked,{i:17 for i in [0,2,4,5]},member_id)
            if checked['gen_utime']<=self.plan['expire_at']+4:continue
            if not checked['verified_governing_key_blocks'] or checked['key_block']:raise RuntimeError('Expiry witness lacks successor finality')
            if not checked['verified_final_certificates'] or any(set(cert['validator_ids'])!={member_id(i) for i in [0,2,4]} or cert['verified_weight']!=51 for cert in checked['verified_final_certificates']):
                raise RuntimeError('Post-expiry finality did not use exactly the three authorized survivors')
            self.receipt.update(phase='qualified_before_interruption',post_expiry_sample=str(target),
                post_expiry_block=checked['block'],post_expiry_certificates=checked['verified_final_certificates'],
                post_expiry_all_six_states_match=True)
            self.save();return checked

    async def complete(self,recovered):
        if getattr(self.args,'expired_member_restart',False):
            if self.receipt['phase']!='qualified_before_interruption':
                raise RuntimeError('Expired restart lacks qualified natural expiry evidence')
            process=self.node['process'];ticks=self.node['start_ticks']
            if process.pid==self.pid or process.returncode is not None or Path(f'/proc/{process.pid}/stat').read_text().split()[21]!=ticks:
                raise RuntimeError('Expired full node did not remain alive as a new process')
            if time.monotonic()>=self.deadline:raise TimeoutError('Expired restart exceeded the original recovery deadline')
            if any(digest(Path(p))!=h for p,h in self.bindings.items()):raise RuntimeError('Expired restart changed signing authority')
            self.receipt.update(phase='expired_member_restarted_without_signing',new_pid=process.pid,new_start_ticks=ticks,
                last_checkpoint=recovered['last_checkpoint'],authority_unchanged=True,old_process_replaced=True,
                full_node_observation=recovered['expired_full_node'])
            self.save();return
        self.alive()
        self.receipt.update(phase='recovered_with_peer_still_expired',last_checkpoint=recovered['last_checkpoint'],
            same_expired_process=True,authority_unchanged=True)
        self.save()
