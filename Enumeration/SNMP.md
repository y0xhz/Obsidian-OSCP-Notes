community.txt (public, private, manager)
```
onesixtyone -c community -i ips
```
run snmpwalk to enumerate MIB Tree
```
snmpwalk -c public -v1 -t 10 IP 
```
	1.3.6.1.2.1.25.1.6.0    (System Processes)
	1.3.6.1.2.1.25.4.2.1.2  (Running Programs)
	1.3.6.1.2.1.25.4.2.1.4  (Processes Path)
	1.3.6.1.2.1.25.2.3.1.4  (Storage Units)
	1.3.6.1.2.1.25.6.3.1.2  (Software Units)
	1.3.6.1.4.1.77.1.2.25   (User Accounts)
	1.3.6.1.2.1.6.13.1.3    (TCP Local Ports)

Extending the Services
```
snmpwalk -c public -v1 192.168.225.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
```
```
snmpwalk -c public -v1 192.168.225.149 hrSWRunParameters
```
We can use snmp-check 
```
snmp-check 192.168.120.94
```
