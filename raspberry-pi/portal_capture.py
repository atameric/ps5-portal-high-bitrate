"""macOS network setup and restoration for one configured, owned device pair."""
import argparse, ipaddress, json, os, re, signal, subprocess, sys, time
from pathlib import Path
from scapy.all import ARP, Ether, conf, get_if_hwaddr, srp
ROOT=Path(__file__).resolve().parent
KEYS=('net.inet.ip.forwarding','net.inet.ip.redirect')
IFACE='en0'
PS5='192.0.2.10'
PORTAL='192.0.2.20'

def validate_config(c):
    if set(c)!={'interface','ps5_ip','portal_ip'}: raise ValueError('Config needs interface, ps5_ip, portal_ip')
    if not re.fullmatch(r'en[0-9]+',c['interface']): raise ValueError('Expected a macOS Ethernet/Wi-Fi interface such as en0')
    ips=[ipaddress.IPv4Address(c[k]) for k in ('ps5_ip','portal_ip')]
    if ips[0]==ips[1] or any(i.is_multicast or i.is_loopback or i.is_unspecified or i.is_reserved or int(i)==0xffffffff for i in ips):
        raise ValueError('Use distinct unicast device IPv4 addresses')
    return c

def configure(c=None):
    global IFACE, PS5, PORTAL
    if sys.platform!='darwin': raise RuntimeError('Live operation requires macOS')
    c=validate_config(c if c is not None else json.loads((ROOT/'config.json').read_text()))
    IFACE,PS5,PORTAL=c['interface'],c['ps5_ip'],c['portal_ip']


def sysread(key): return subprocess.check_output(['/usr/sbin/sysctl','-n',key],text=True).strip()

def syswrite(key,value): subprocess.run(['/usr/sbin/sysctl','-w',f'{key}={value}'],check=True,stdout=subprocess.DEVNULL)

def mac(ip):
    subprocess.run(['/sbin/ping','-c','1','-W','1000',ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    text=subprocess.run(['/usr/sbin/arp','-n',ip],text=True,capture_output=True).stdout
    match=re.search(rf' at ([0-9a-f:]+) on {re.escape(IFACE)}\b',text)
    if not match and os.geteuid()==0:
        own=get_if_hwaddr(IFACE)
        answers,_=srp(Ether(src=own,dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),iface=IFACE,timeout=2,retry=1,verbose=False)
        found={r[ARP].hwsrc.lower() for _,r in answers if ARP in r and r[ARP].psrc==ip and r[ARP].op==2}
        if len(found)==1: return found.pop()
    if not match: raise RuntimeError(f'{ip}: MAC resolution requires local sudo; no network changes made')
    parts=match[1].split(':')
    if len(parts)!=6: raise RuntimeError('Invalid MAC')
    return ':'.join(f'{int(x,16):02x}' for x in parts)

def frames(state,restore=False):
    own=state['own_mac']; a=state['ps5_mac']; b=state['portal_mac']
    return [Ether(src=own,dst=a)/ARP(op=2,psrc=PORTAL,pdst=PS5,hwsrc=b if restore else own,hwdst=a),
            Ether(src=own,dst=b)/ARP(op=2,psrc=PS5,pdst=PORTAL,hwsrc=a if restore else own,hwdst=b)]

def restore(state):
    configure(state['config'])
    errors=[]
    try:
        s=conf.L2socket(iface=IFACE)
        try:
            for _ in range(3):
                for p in frames(state,True): s.send(p)
                time.sleep(.1)
        finally: s.close()
    except Exception as e: errors.append('ARP restore: '+str(e))
    for key in KEYS:
        try: syswrite(key,state['sysctl'][key])
        except Exception as e: errors.append(key+': '+str(e))
    return errors

def preflight():
    for ip in (PS5,PORTAL):
        route=subprocess.check_output(['/sbin/route','-n','get',ip],text=True)
        if re.search(r'flags:.*GATEWAY',route): raise RuntimeError('Both devices must be on the directly connected LAN')
        if not re.search(rf'interface:\s+{re.escape(IFACE)}\b',route): raise RuntimeError('Unexpected network interface')
    state={'config':{'interface':IFACE,'ps5_ip':PS5,'portal_ip':PORTAL},'own_mac':get_if_hwaddr(IFACE),'ps5_mac':mac(PS5),'portal_mac':mac(PORTAL),
           'sysctl':{k:sysread(k) for k in KEYS}}
    if len(set(state[k] for k in ('own_mac','ps5_mac','portal_mac')))!=3: raise RuntimeError('MAC addresses not distinct')
    if any(v not in ('0','1') for v in state['sysctl'].values()): raise RuntimeError('Unexpected sysctl value')
    return state

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--watchdog',type=Path)
    p.add_argument('--restore',type=Path)
    p.add_argument('--check',action='store_true')
    a=p.parse_args()
    if os.geteuid()!=0: p.error('Run with sudo from your local Terminal')
    if a.watchdog or a.restore:
        if a.watchdog:
            signal.signal(signal.SIGHUP,signal.SIG_IGN)
            time.sleep(55)
        path=a.watchdog or a.restore
        errors=restore(json.loads(path.read_text()))
        path.with_suffix('.result.json').write_text(json.dumps({'restoration_errors':errors}))
        print('Restoration complete' if not errors else errors)
        sys.exit(1 if errors else 0)
    configure()
    preflight()
    print('Preflight passed. No network settings changed.')
