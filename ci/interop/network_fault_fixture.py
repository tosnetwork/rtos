#!/usr/bin/env python3
"""Mixed-node packet faults with native proofs and unchanged process identities."""
import asyncio
import json
from pathlib import Path
import re
import time
import urllib.error

from mixed_matrix import child_checked, cpp_block, cpp_certificate, digest, identity, native_state, rpc, write
from network_faults import PacketFault


async def stop_cpp_with_receipt(index, node):
    # Pinned 8f083dc tostester owns the actual subprocess behind this field.
    # Capture it before stop() clears it; do not infer success from a missing PID.
    process = node._Node__process
    started = time.monotonic()
    task = asyncio.create_task(node.stop())
    try:
        await asyncio.wait_for(asyncio.shield(task), 20)
    except TimeoutError:
        process.kill()
        await process.wait()
        await task
    return index, {'returncode': process.returncode,
        'elapsed_seconds': time.monotonic() - started, 'normal_exit_limit_seconds': 20}


async def exercise_network_member(args, root, nodes, endpoints, lite_configs, rust_nodes,
                                  zero, governing, checkpoint, artifacts):
    from rotation_fixture import SUCCESSOR, member_id, recovery_workchain_states
    index = args.network_fault_member
    rust = next((node for node in rust_nodes if node['index'] == index), None)
    pid = rust['process'].pid if rust else nodes[index].process_id
    start_ticks = Path(f'/proc/{pid}/stat').read_text().split()[21]

    def same_process():
        if not Path(f'/proc/{pid}/stat').exists() or Path(f'/proc/{pid}/stat').read_text().split()[21] != start_ticks:
            raise RuntimeError('Packet fault changed the selected process')
        if rust and rust['process'].returncode is not None:
            raise RuntimeError('Isolated Rust member exited')

    directory = root / 'network-fault'; directory.mkdir()
    config = json.loads((rust['directory'] / 'default_config.json').read_text()) if rust else None
    if config:
        ports = [int(config[key].rsplit(':',1)[1]) for key in ['ip_address','ip_address_quic']]
        ports += [int(config['json_rpc_server']['address'].rsplit(':',1)[1]),int(config['lite_server_port'])]
    else:
        # C++ consensus listeners plus its control endpoint. Marked outgoing
        # sockets/conntrack cover other established and ephemeral connections.
        model = json.loads((nodes[index].directory / 'config.json').read_text())
        ports = [entry['port'] for entry in model.get('addrs',[])]
        ports += [entry['port'] for entry in model.get('liteservers',[])]
        ports += [entry['port'] for entry in model.get('control',[])]
        ports += [int(endpoints[index].split(':')[2].split('/')[0])]
    fault = PacketFault(directory / 'injection',args.network_fault,ports)
    receipt = {'mode':args.network_fault,'member':index,'process':{'pid':pid,'start_ticks':start_ticks},
        'before':checkpoint['block'],'phase':'arming','same_process':True,
        'manual_database_repair':False,'deadline_seconds':args.recovery_timeout}
    write(directory / 'receipt.json',receipt)
    deadline = time.monotonic() + args.recovery_timeout
    histories = [{} for _ in nodes]

    async def common(indices, floor):
        while time.monotonic() < deadline:
            same_process()
            replies = await asyncio.gather(*(asyncio.to_thread(rpc,endpoints[i],'getMasterchainInfo') for i in indices),
                                           return_exceptions=True)
            for i,value in zip(indices,replies):
                if isinstance(value,BaseException):continue
                if identity(value['init']) != identity(zero):raise RuntimeError('Packet fault endpoint changed Genesis')
                histories[i][identity(value['last'])]=value
                if len(histories[i])>512:del histories[i][next(iter(histories[i]))]
            shared=set.intersection(*(set(histories[i]) for i in indices))
            newer=[key for key in shared if key[2]>floor]
            if newer:
                key=max(newer,key=lambda key:key[2]);infos={i:histories[i][key] for i in indices}
                if len({value['state_root_hash'] for value in infos.values()})!=1:
                    raise RuntimeError('Packet fault peers disagree on the applied state')
                return infos
            await asyncio.sleep(0.2)
        raise TimeoutError('Packet fault did not recover within the original recovery deadline')

    async def check(infos,label,with_wc):
        target=directory/label;target.mkdir()
        write(target/'references.json',{str(i):v for i,v in infos.items()})
        block_id=infos[0]['last']
        block=await cpp_block(args.snapshot,nodes[0],block_id,target)
        state=await native_state(args.snapshot,lite_configs[0],'cpp-0',block_id,target/'mc-state')
        proof=await cpp_certificate(args.snapshot,nodes[0],zero,block_id,target)
        sample={'zerostate':zero,'reference':infos[0],'comparison':infos[next(i for i in infos if i!=0)],
            'all_references':{str(i):v for i,v in infos.items()},'block':block,'masterchain_state':state,
            'certificates':[proof],'governing_key_block':{**governing,'certificates':[proof]}}
        write(target/'sample.json',sample)
        await child_checked([args.block_checker,target/'sample.json',target/'checked.json'],target/'checker.log')
        checked=json.loads((target/'checked.json').read_text())
        if {v['validator_id'] for v in checked['configuration']['current']['members']}!={member_id(i) for i in SUCCESSOR}:
            raise RuntimeError('Packet fault checkpoint changed the successor committee')
        if not checked['verified_governing_key_blocks'] or checked['key_block']:
            raise RuntimeError('Packet fault lacks successor finality')
        if with_wc:
            tops=[top for top in checked['shard_tops'] if top['workchain']==0 and top['seqno']>0]
            if len(tops)!=1:raise RuntimeError('Packet recovery requires one full workchain')
            wc=target/'workchain';wc.mkdir()
            sample['references']={str(i):infos[i] for i in SUCCESSOR}
            sample['workchain']={'block':await cpp_block(args.snapshot,nodes[0],tops[0],wc),
                'states':await recovery_workchain_states(args.snapshot,lite_configs,SUCCESSOR,tops[0],wc,deadline)}
            write(target/'sample.json',sample)
            await child_checked([args.block_checker,target/'sample.json',target/'checked-with-workchain.json'],
                                target/'workchain-checker.log')
            checked=json.loads((target/'checked-with-workchain.json').read_text())
        return checked

    armed=time.time()
    try:
        fault.arm();armed=fault.armed_at
        receipt.update(phase='isolated',armed_at_unix=armed);write(directory/'receipt.json',receipt)
        if args.network_fault == 'partition':
            try:
                await asyncio.to_thread(rpc, endpoints[index], 'getMasterchainInfo')
            except (TimeoutError, urllib.error.URLError) as error:
                if isinstance(error, urllib.error.URLError) and not isinstance(error.reason, TimeoutError):
                    raise
                receipt['isolated_rpc_timeout_observed'] = True
                write(directory/'receipt.json',receipt)
            else:
                raise RuntimeError('Selected process control TCP endpoint bypassed the packet partition')
        # Wait in the same absolute recovery budget; no new budget on restoration.
        while time.time()<armed+args.network_fault_seconds:
            same_process();await asyncio.sleep(0.2)
        survivors=[i for i in range(6) if i!=index]
        floor=checkpoint['block']['seqno']
        while True:
            infos=await common(survivors,floor);floor=infos[0]['last']['seqno']
            checked=await check(infos,f'isolated-{floor}',False)
            if checked['gen_utime']>armed:break
        certificates=checked['verified_final_certificates']
        if args.network_fault=='partition':
            for certificate in certificates:
                if member_id(index) in certificate['validator_ids']:
                    raise RuntimeError('Isolated member still signed the fresh survivor checkpoint')
            active={m['validator_id']:m['weight'] for m in checked['configuration']['current']['members']}
            if any(set(cert['validator_ids']) != {member_id(i) for i in SUCCESSOR if i!=index} for cert in certificates):
                raise RuntimeError('Partition certificate did not prove exactly the surviving quorum')
            receipt['surviving_weight']=sum(w for identity,w in active.items() if identity!=member_id(index))
            receipt['total_weight']=sum(active.values())
        stats=fault.statistics()
        if args.network_fault in ['partition','loss'] and stats['drops']<=0:
            raise RuntimeError('Packet-loss injection was not observed by the kernel')
        if args.network_fault in ['reorder','duplicate'] and stats['packets']<=0:
            raise RuntimeError('Packet impairment carried no traffic')
        receipt.update(survivor_checkpoint=checked['block'],survivor_certificates=certificates,kernel_statistics=stats)
    finally:
        if fault.owned:fault.restore()
        receipt['restored_at_unix']=time.time();write(directory/'receipt.json',receipt)
    restored=receipt['restored_at_unix'];same_process()
    receipt['phase']='waiting_for_reconnected_member';write(directory/'receipt.json',receipt)
    histories=[{} for _ in nodes];leaders={};vote=None
    minimum_wc=max((top['seqno'] for top in checked['shard_tops'] if top['workchain']==0),default=0)
    while len(leaders)<2 or vote is None:
        infos=await common(list(range(6)),floor);floor=infos[0]['last']['seqno']
        checked=await check(infos,str(floor),True)
        if checked['gen_utime']>restored and any(member_id(index) in cert['validator_ids'] for cert in checked['verified_final_certificates']):
            vote={'block':checked['block'],'sample_directory':str(directory/str(floor))}
        for chain,evidence in [('masterchain',checked),('workchain',checked['workchain_check'])]:
            if evidence['created_by']!=member_id(index) or evidence['gen_utime']<=restored:continue
            if chain=='workchain' and evidence['block']['seqno']<=minimum_wc:continue
            item={'block':evidence['block'],'sample_directory':str(directory/str(floor))}
            if rust:
                workchain=-1 if chain=='masterchain' else 0
                match=re.search(r'^\('+str(workchain)+r':8000000000000000, '+str(evidence['block']['seqno'])+
                    r'\): ValidatorGroup::on_generate_slot: .*Collation successful$',
                    (rust['directory']/'node.log').read_text(errors='replace'),re.M)
                if not match:raise RuntimeError('Reconnected Rust creator lacks local collation evidence')
                item['local_collation']=match.group(0)
            leaders.setdefault(chain,item)
        receipt.update(leaders=leaders,vote=vote,last_checkpoint=checked['block'])
        write(directory/'receipt.json',receipt)
    same_process()
    for filename,expected in artifacts.items():
        if digest(Path(filename))!=expected:raise RuntimeError('Packet exercise changed an executable or frozen input')
    receipt.update(phase='recovered',same_process=True,all_six_applied_states_match=True,
        workchain_states_match=True,successor_finality_checked=True)
    write(directory/'receipt.json',receipt)
    return receipt
