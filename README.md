# arp_spoofer.py
Simple python3 arp spoofing script
```
To make sure IP forwarding is enabled, run this command as root:
echo 1 > /proc/sys/net/ipv4/ip_forward
```

```
[*] Usage (run as root):
sudo python3 arp_spoofer.py <arguments>
-t (--target):              specify target's local ip address
-m (--mac):                 attacker's mac address
-g (--gateway):             gateway's ip address
-b (--broadcast)[optional]: network broadcast
-i (--interval)[optinal]:   interval between packets
-c (--count)[optional]:     ammount of packets to send (default 100)
```
