# Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
"""Sign generator output using the public test signer; never production keys."""
import hashlib,json,struct,subprocess,sys
from pathlib import Path
source,signer,destination=map(Path,sys.argv[1:])
data=json.loads(source.read_text())
expected_key=json.loads((Path(__file__).resolve().parents[1]/'tests/data/pq-finality-keys.json').read_text())[1]
for row in data['cases']:
 candidate=bytes.fromhex(row['candidate'])
 cid=struct.pack('<II',0xb691cd3f,row['slot'])+hashlib.sha256(candidate).digest()
 vote=struct.pack('<I',0x40a7e105)+cid
 pre=struct.pack('<I',0xa8e33df8)+bytes.fromhex(row['session'])+bytes([len(vote)])+vote+b'\0'*3
 assert len(pre)==84 and pre.hex()==row['preimage']
 signed=subprocess.check_output([str(signer),'1',pre.hex(),b'TOS-CONSENSUS-SIMPLEX-v1'.hex()],text=True).splitlines()
 assert signed[0] == expected_key, 'public fixture signer key does not match the history validator set'
 row['signature']=signed[-1]
 assert len(bytes.fromhex(row['signature']))==2420
destination.write_text(json.dumps(data,indent=2)+'\n')
