#!/usr/bin/env python3
"""One bounded, hypothesis-driven Portal LaunchSpec byte mutation.
Candidate offsets from static Sony templates, NOT verified Portal plaintext.
0x04 would change leading ASCII '2' to '6' if request is 25000 at that position.
Raw Ethernet forwarding only for the two authorized local devices; no scanning.
"""
import argparse, base64, collections, datetime, json, os, signal, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path
from scapy.all import conf
import portal_capture as network
from protocol import fields
from protocol import readvar
from portal_egress_witness import Witness

PREFIX=b'{"sessionId":"sessionId4321","streamResolutions":[{"resolution":{"width":1920,"height":1080},"maxFps":60,"score":10}],"network":{"bwKbpsSent":'
OFFSET=334
PATCH_DELTA=bytes([4])
CONFIRM_TARGET=50000000
PROFILE_LABEL='65mbps'

def mutate(data):
    if len(data)<32 or data[0]!=0 or data[13]!=0 or data[14] not in (0,1): return data,False
    if data[5:9]!=b'\0'*4 or data[21:26]!=b'\0'*5 or data[26:29]!=b'\x08\0\x12': return data,False
    if len(data)!=int.from_bytes(data[15:17],'big')+13:return data,False
    try:
        _,pos=readvar(data,29)
        tag,pos=readvar(data,pos); version,pos=readvar(data,pos)
        if tag!=8 or version!=20:return data,False
        while pos<len(data):
            tag,pos=readvar(data,pos)
            if tag&7!=2:return data,False
            size,pos=readvar(data,pos)
            if tag>>3==3:
                # Recorded Portal shape. Abort mutation for any other layout.
                if size!=2296:return data,False
                lo=OFFSET//3*3; a=pos+lo//3*4
                end=((OFFSET+len(PATCH_DELTA)+2)//3)*3
                b=pos+end//3*4
                if b>len(data):return data,False
                raw=bytearray(base64.b64decode(data[a:b],validate=True))
                for i,delta in enumerate(PATCH_DELTA):raw[OFFSET-lo+i]^=delta
                return data[:a]+base64.b64encode(raw)+data[b:],True
            pos+=size
    except (ValueError,IndexError): pass
    return data,False


def checksum(b):
    if len(b)%2:b+=b'\0'
    n=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while n>>16:n=(n&65535)+(n>>16)
    return (~n)&65535


def transform(frame,state,active=False):
    """Return outbound Ethernet bytes, observed UDP bytes/direction, mutation flag."""
    own=bytes.fromhex(state['own_mac'].replace(':',''))
    if len(frame)<34 or frame[:6]!=own or frame[12:14]!=b'\x08\0':return None
    ip=frame[14:]; ihl=(ip[0]&15)*4; total=int.from_bytes(ip[2:4],'big')
    if ip[0]>>4!=4 or ihl<20 or total<ihl or len(ip)<total:return None
    src,dst=socket.inet_ntoa(ip[12:16]),socket.inet_ntoa(ip[16:20])
    if (src,dst)==(network.PORTAL,network.PS5): dest=state['ps5_mac'];direction='out'
    elif (src,dst)==(network.PS5,network.PORTAL): dest=state['portal_mac'];direction='in'
    else:return None
    payload=None;changed=False
    if ip[9]==17 and not int.from_bytes(ip[6:8],'big')&0x3fff and total>=ihl+8:
        udp=ip[ihl:total]; sport,dport,n,_=struct.unpack('!HHHH',udp[:8])
        if 8<=n<=len(udp) and 9296 in (sport,dport):
            payload=udp[8:n]
            if active and direction=='out':
                new,changed=mutate(payload)
                if changed:
                    udp=udp[:6]+b'\0\0'+new
                    pseudo=ip[12:20]+b'\0\x11'+struct.pack('!H',len(udp))
                    cs=checksum(pseudo+udp) or 65535
                    udp=udp[:6]+struct.pack('!H',cs)+udp[8:]
                    ip=ip[:ihl]+udp
    outbound=bytes.fromhex(dest.replace(':',''))+own+frame[12:14]+ip
    return outbound,payload,direction,changed


def observe(data,events):
    if len(data)<28 or data[0]&15 or data[13]!=0 or data[14]!=1 or data[25]!=0:return
    try:
        f=fields(data[26:]);kind=f.get(1)
        if kind==1:
            q=fields(f[3]); events.append({'type':'BANG','version':q.get(1),'key_accepted':q.get(3),'version_accepted':q.get(4)})
        elif kind==13:events.append({'type':'STREAMINFO'})
        elif kind==16:events.append({'type':'CONNECTIONQUALITY','target_bitrate_raw':fields(f[17]).get(1)})
        elif kind==8:events.append({'type':'DISCONNECT'})
    except (ValueError,TypeError,KeyError):pass


class TargetConfirmation:
    """Only confirm quality reports belonging to a newly modified session."""
    def __init__(self):
        self.armed=False;self.accepted=False;self.streaming=False;self.samples=0

    def modified(self):
        self.armed=True;self.accepted=False;self.streaming=False;self.samples=0

    def observe(self,event):
        if event['type']=='DISCONNECT':
            self.__init__()
        elif event['type']=='BANG':
            self.accepted=self.armed and event.get('key_accepted')==1 and event.get('version_accepted')==1
            self.streaming=False;self.samples=0
        elif event['type']=='STREAMINFO' and self.accepted:
            self.streaming=True
        elif event['type']=='CONNECTIONQUALITY' and self.accepted and self.streaming:
            self.samples=self.samples+1 if event.get('target_bitrate_raw',0)>=CONFIRM_TARGET else 0

    @property
    def ready(self):
        return self.samples>=3


def run(active, finish_on_high_target=False):
    if os.geteuid()!=0:raise RuntimeError('Use local Terminal launcher with sudo')
    uid,gid=int(os.environ['SUDO_UID']),int(os.environ['SUDO_GID']);os.umask(0o077)
    network.configure()
    state=network.preflight()
    # Never interrupt existing routing services.
    if state['sysctl']['net.inet.ip.forwarding']!='0':raise RuntimeError('Forwarding already active; stop before any changes')
    lock=Path('/var/run/portal-lab-capture.lock');fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
    folder=network.ROOT/'experiments'/('portal-'+('patch-' if active else 'baseline-')+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    folder.mkdir(mode=0o700, parents=True)
    saved=Path(tempfile.mkdtemp(prefix='portal-lab-restore-',dir='/var/tmp'))/'state.json';saved.write_text(json.dumps(state))
    rx=tx=watcher=witness=None;altered=False;errors=[];counts=collections.Counter();events=[];rates=collections.Counter();start=time.monotonic();seen=set();completed=False
    confirmation=TargetConfirmation()
    def interrupted(sig,frame):raise KeyboardInterrupt
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    try:
        filt=f'ether dst {state["own_mac"]} and ip and host {network.PS5} and host {network.PORTAL}'
        rx=conf.L2listen(iface=network.IFACE,filter=filt);tx=conf.L2socket(iface=network.IFACE)
        witness=Witness(folder,state,network.IFACE,network.PS5,network.PORTAL)
        watcher=subprocess.Popen([sys.executable,str(network.ROOT/'portal_capture.py'),'--watchdog',str(saved)],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        altered=True;network.syswrite('net.inet.ip.redirect','0')
        # Forwarding stays OFF: only these two peers are relayed, with no original duplicate.
        duration=40 if active else 20
        print('Preparing network path; keep Portal disconnected.',flush=True)
        start=time.monotonic();end=start+duration;next_arp=0
        ready_at=start+5;ready_announced=False;early_session_warned=False
        while time.monotonic()<end:
            now=time.monotonic()
            if now>=next_arp:
                for p in network.frames(state):tx.send(p)
                next_arp=now+1
            if not ready_announced and now>=ready_at:
                ready_announced=True
                print(('EXPERIMENT' if active else 'BASELINE')+
                      f' READY: connect Portal to PS5 now. At most {duration-5} seconds remaining.',flush=True)
            if not rx.select([rx],remain=.05):continue
            _,frame,stamp=rx.recv_raw()
            if not frame:continue
            result=transform(frame,state,active)
            if result is None:continue
            outbound,data,direction,changed=result
            tx.send(outbound);counts['forwarded_'+direction]+=1
            if changed:
                witness.expect(outbound)
                counts['mutated_packets_including_retransmits']+=1
                if data[17:21] not in seen:confirmation.modified()
                seen.add(data[17:21])
                if counts['mutated_packets_including_retransmits']==1:
                    print('Startup packet modified; waiting for PS5 response.',flush=True)
            if data is not None and direction=='in':
                rates[int(now-start)]+=len(data)
                observed=[];observe(data,observed);events.extend(observed)
                for event in observed:
                    confirmation.observe(event)
                    if active and not seen and not early_session_warned and event['type']=='CONNECTIONQUALITY':
                        early_session_warned=True
                        print('Stream detected without modified startup. Disconnect Portal and reconnect.',flush=True)
                if active and finish_on_high_target and confirmation.ready:
                    print('PS5 reported high target bitrate. Restoring direct connection.',flush=True)
                    break
        completed=True
    except KeyboardInterrupt:print('Stopping; restoring original network state.',flush=True)
    finally:
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
        if altered:errors=network.restore(state)
        if witness:witness.stop()
        for sock in (rx,tx):
            if sock:sock.close()
        if watcher and not errors:
            watcher.terminate();watcher.wait(timeout=3)
        if not errors:lock.unlink(missing_ok=True)
        report={'mode':'candidate_byte_probe' if active else 'baseline','completed':completed,'candidate_plaintext_offset':OFFSET if active else None,'xor_mask':4 if active else None,'candidate_is_verified_portal_plaintext':False,'counts':dict(counts),'unique_mutated_sequences':len(seen),'ps5_messages':events,'udp_9296_mbps_by_second':{str(k):round(v*8/1e6,3) for k,v in sorted(rates.items())},'restoration_errors':errors,'sysctl_after':{k:network.sysread(k) for k in network.KEYS},'egress_witness':witness.report() if witness else None,'limits':['Candidate offset is a static template hypothesis, not decrypted Portal data.','Target bitrate is a console report, not a pure video throughput measure.','User-space relay latency/loss is not independently measured.']}
        report['xor_mask']=PATCH_DELTA[0] if active and len(PATCH_DELTA)==1 else None
        report['xor_bytes_hex']=PATCH_DELTA.hex() if active else None
        report['profile']=PROFILE_LABEL
        report['directory']=str(folder)
        report['watchdog_state']=str(saved)
        report['high_target_confirmed']=confirmation.ready
        for artifact in folder.iterdir():os.chown(artifact,uid,gid)
        (folder/'report.json').write_text(json.dumps(report,indent=2)+'\n');os.chown(folder/'report.json',uid,gid);os.chown(folder,uid,gid)
        print(json.dumps(report,indent=2));print('Report:',folder/'report.json',flush=True)

    return report

def main():
    global OFFSET, PATCH_DELTA, CONFIRM_TARGET, PROFILE_LABEL
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=('65','100','200'),default='65')
    args=parser.parse_args()
    OFFSET=334
    PATCH_DELTA={'65':b'\x04','100':bytes.fromhex('03501b0005'),'200':bytes.fromhex('00501b0005')}[args.profile]
    CONFIRM_TARGET={'65':50000000,'100':80000000,'200':160000000}[args.profile]
    PROFILE_LABEL=args.profile+'mbps_experimental'
    report=run(True,finish_on_high_target=True)
    if report['restoration_errors']:
        print('RESTORATION FAILED. See recovery instructions in README.');return 2
    if not report['unique_mutated_sequences']:
        print('NOT APPLIED: no matching fresh handshake. Disconnect and retry after READY.');return 1
    if not report['high_target_confirmed']:
        print(f'UNCONFIRMED: mutation sent, but three consecutive targets >= {CONFIRM_TARGET/1e6:g} Mbps were not observed. This does not mean the session failed.');return 1
    print('Target confirmed. This is not a measurement of actual video bitrate.');return 0

if __name__=='__main__': sys.exit(main())
