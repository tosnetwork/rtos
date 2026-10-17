#!/usr/bin/env python3
"""Kernel packet partition: bidirectional UDP/TCP, old connections, recovery and controls."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from network_faults import MARK, PacketFault, PacketMarks, marked_environment, require_namespace

CHILD = r'''
import json,socket,sys,threading
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('127.0.0.1',0))
t=socket.socket();t.bind(('127.0.0.1',0));t.listen()
out=socket.socket();out.connect(('127.0.0.1',int(sys.argv[1])))
def echo(c):
 while True:
  value=c.recv(1024)
  if not value:return
  c.sendall(value)
def udp():
 while True:
  value,peer=u.recvfrom(1024);u.sendto(value,peer)
def tcp():
 while True:
  c,_=t.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
threading.Thread(target=udp,daemon=True).start()
threading.Thread(target=tcp,daemon=True).start()
threading.Thread(target=echo,args=(out,),daemon=True).start()
print(json.dumps(dict(udp=u.getsockname()[1],tcp=t.getsockname()[1],
 marks=[s.getsockopt(socket.SOL_SOCKET,36) for s in [u,t,out]])),flush=True)
sys.stdin.read()
'''


class NamespaceGuardTests(unittest.TestCase):
    def test_host_or_missing_namespace_is_refused(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'host changes refused'):
                require_namespace()


@unittest.skipUnless(os.environ.get('RTOS_FIXTURE_PARENT_NETNS'), 'Run through run_network_namespace.py')
class KernelPartitionTests(unittest.TestCase):
    def test_real_partition_and_recovery_without_process_restart(self):
        library = Path(os.environ['RTOS_TEST_SOCKET_MARK_LIBRARY']).resolve()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            routing = PacketMarks(root / 'routing'); routing.prepare()
            child = None
            fault = None
            sockets = []
            try:
                listener = socket.socket(); sockets.append(listener)
                listener.bind(('127.0.0.1',0)); listener.listen(); listener.settimeout(3)
                child = subprocess.Popen([sys.executable, '-c', CHILD, str(listener.getsockname()[1])],
                    env=marked_environment(library), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                connection, _ = listener.accept(); sockets.append(connection)
                settings = json.loads(child.stdout.readline())
                self.assertEqual(settings['marks'], [int(MARK,0)]*3)
                udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sockets.append(udp)
                udp.settimeout(2)
                address = ('127.0.0.1',settings['udp'])
                udp.sendto(b'before',address); self.assertEqual(udp.recv(100),b'before')
                connection.settimeout(2); connection.sendall(b'before')
                self.assertEqual(connection.recv(100),b'before')
                incoming = socket.create_connection(('127.0.0.1',settings['tcp'])); sockets.append(incoming)
                incoming.sendall(b'before'); self.assertEqual(incoming.recv(100),b'before')
                fault = PacketFault(root/'partition','partition',[settings['udp'],settings['tcp']]); fault.arm()
                for channel in [connection,incoming]:
                    channel.settimeout(0.3); channel.sendall(b'during')
                    with self.assertRaises(TimeoutError):channel.recv(100)
                udp.settimeout(0.3);udp.sendto(b'during',address)
                with self.assertRaises(TimeoutError):udp.recv(100)
                # A fresh socket cannot bypass the listening-port filters.
                new_udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sockets.append(new_udp)
                new_udp.settimeout(0.3);new_udp.sendto(b'new',address)
                with self.assertRaises(TimeoutError):new_udp.recv(100)
                new_tcp=socket.socket();sockets.append(new_tcp);new_tcp.settimeout(0.3)
                with self.assertRaises(TimeoutError):new_tcp.connect(('127.0.0.1',settings['tcp']))
                # Unmarked control traffic in the same namespace continues.
                left=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);right=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                sockets.extend([left,right]);right.bind(('127.0.0.1',0));right.settimeout(1)
                left.sendto(b'control',right.getsockname());self.assertEqual(right.recv(100),b'control')
                self.assertIsNone(child.poll());self.assertGreater(fault.statistics()['drops'],0)
                fault.restore()
                for channel in [connection,incoming]:
                    channel.settimeout(5);self.assertEqual(channel.recv(100),b'during')
                udp.settimeout(2);udp.sendto(b'after',address);self.assertEqual(udp.recv(100),b'after')
                self.assertIsNone(child.poll())
            finally:
                if fault and fault.owned:fault.restore()
                for item in sockets:item.close()
                if child:
                    child.stdin.close();child.wait(timeout=5);child.stdout.close()
                routing.close()


    def test_loss_reorder_and_duplicate_are_observed_packets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);routing=PacketMarks(root/'routing');routing.prepare()
            try:
                for mode,count in [('loss',128),('reorder',32),('duplicate',32)]:
                    with self.subTest(mode=mode):
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
                            sender.bind(('127.0.0.1',0));receiver.bind(('127.0.0.1',0));receiver.settimeout(0.5)
                            sender.setsockopt(socket.SOL_SOCKET,36,int(MARK,0))
                            fault=PacketFault(root/mode,mode,[sender.getsockname()[1]])
                            try:
                                fault.arm()
                                for number in range(count):sender.sendto(bytes([number]),receiver.getsockname())
                                values=[]
                                while True:
                                    try:values.append(receiver.recv(100)[0])
                                    except TimeoutError:break
                                stats=fault.statistics()
                                if mode=='loss':
                                    self.assertGreater(stats['drops'],0);self.assertGreater(len(values),0);self.assertLess(len(values),count)
                                elif mode=='reorder':
                                    self.assertEqual(sorted(values),list(range(count)));self.assertNotEqual(values,list(range(count)))
                                else:
                                    self.assertEqual(sorted(values),sorted(list(range(count))*2))
                            finally:fault.restore()
            finally:routing.close()


if __name__ == '__main__':
    unittest.main()
