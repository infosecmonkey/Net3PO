// Built-in sample texts for trying recipes, ported from macGREP and extended
// with network device logs. All addresses are private or documentation ranges.

export interface SampleDoc {
  name: string;
  text: string;
}

const networkConfig = `hostname core-sw-01
!
interface Vlan10
 description Users
 ip address 10.10.10.1 255.255.255.0
 ipv6 address 2001:db8:10::1/64
 ip igmp static-group 239.1.1.5
!
interface Vlan20
 description Servers
 ip address 10.10.20.1 255.255.254.0
 ip helper-address 10.10.99.5
!
interface GigabitEthernet0/1
 description Uplink to fw-01 (00:1a:2b:3c:4d:5e)
 switchport trunk allowed vlan 10,20,4094
 ip address 192.168.100.2 255.255.255.252
 mac-address 0050.56ab.cdef
!
ip route 0.0.0.0 0.0.0.0 192.168.100.1
ip route 172.16.0.0 255.240.0.0 10.10.20.254
!
access-list 101 permit ip 10.10.10.0 0.0.0.255 any
access-list 101 deny   ip 192.168.0.0 0.0.255.255 any
access-list 101 permit tcp any host 203.0.113.10 eq 443
!
router bgp 64512
 neighbor 100.64.0.1 remote-as 64513
!
ntp server 216.239.35.0
logging host 10.10.99.20 transport udp port 5514
ip nat inside source static tcp 10.10.20.10 443 203.0.113.10:8443 extendable
snmp-server host 10.10.99.21 version 2c public
!
# Firewall rules
allow from 10.0.0.0/8 to 10.10.99.0/24 port 22
allow from 192.168.1.0/24 to 0.0.0.0/0 port 80,443
deny  from 169.254.0.0/16 to any
allow from fe80::/10 to ff02::1
allow from 2001:db8::/32 to 2001:db8:10::1/128
bad   from 256.1.1.1 to 10.10.10.999`;

const fortigateLog = `date=2026-10-29 time=08:14:02 devname="FGT-HQ" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.25 srcport=51234 srcintf="internal" dstip=198.51.100.53 dstport=53 dstintf="wan1" policyid=5 proto=17 action="accept" service="DNS" sentbyte=74 rcvdbyte=90
date=2026-10-29 time=08:14:05 devname="FGT-HQ" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.20.10 srcport=443 srcintf="dmz" dstip=203.0.113.9 dstport=60211 dstintf="wan1" policyid=12 proto=6 action="close" service="HTTPS" sentbyte=48211 rcvdbyte=1932
date=2026-10-29 time=08:14:09 devname="FGT-HQ" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" srcip=192.168.1.77 srcport=49822 srcintf="guest" dstip=10.10.20.5 dstport=445 dstintf="dmz" policyid=0 proto=6 action="deny" service="SMB" msg="Denied by forward policy check (policy 0)"
date=2026-10-29 time=08:14:12 devname="FGT-HQ" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" action="tunnel-up" remip=198.51.100.200 tunnelip=100.64.10.2 vpntunnel="branch-01"
date=2026-10-29 time=08:14:20 devname="FGT-HQ" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.31 srcport=55012 srcintf="internal" dstip=203.0.113.80 dstport=80 dstintf="wan1" policyid=5 proto=6 action="server-rst" service="HTTP" transip=198.51.100.2 transport=55012`;

const ciscoSyslog = `<189>Oct 29 08:14:02 core-sw-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
<189>Oct 29 08:14:03 core-sw-01 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down
<190>Oct 29 08:14:05 core-sw-01 %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.10.99.5)
<187>Oct 29 08:14:11 core-sw-01 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/24 with BPDU Guard enabled. Disabling port.
<188>Oct  9 08:15:00 dist-sw-02 %SW_MATM-4-MACFLAP_NOTIF: Host 0050.56ab.cdef in vlan 20 is flapping between port Te1/1/1 and port Po10
<189>Oct 29 08:15:42 edge-rtr-01 %BGP-5-ADJCHANGE: neighbor 100.64.0.1 Down BGP Notification sent
<187>Oct 29 08:16:03 edge-rtr-01 %DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 10.10.30.2 (Tunnel10) is up: new adjacency
<190>2026-10-29T08:16:30.412-04:00 lab-arista-01 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet49/1, changed state to up`;

const serverLog = `2026-10-29T08:14:02Z INFO  server started on port 8080
2026-10-29T08:14:09Z INFO  GET /api/users/42 200 12ms 192.168.1.20
2026-10-29T08:14:11Z WARN  slow query took 812ms
2026-10-29T08:14:15Z ERROR GET /api/orders/9001 500 4ms 10.0.0.7
2026-10-29T08:14:16Z INFO  POST /api/login 401 3ms 203.0.113.9 user=alice@example.com
2026-10-29T08:14:31Z ERROR connection refused: db-primary.example.com:5432
2026-10-29T08:14:58Z WARN  retrying job 5f1c2a9e-8b7d-4c3e-9f0a-1b2c3d4e5f60 (attempt 2)
2026-10-29T08:15:00Z INFO  GET /healthz 200 1ms 127.0.0.1
2026-10-29T08:15:12Z ERROR POST https://api.example.com/v1/payments 502 31ms 198.51.100.23 upstream timeout`;

export const SAMPLES: SampleDoc[] = [
  { name: "Network config", text: networkConfig },
  { name: "FortiGate traffic log", text: fortigateLog },
  { name: "Cisco / Arista syslog", text: ciscoSyslog },
  { name: "Server log", text: serverLog },
];
