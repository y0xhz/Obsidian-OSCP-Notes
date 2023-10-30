## DNS Enumeration
Find IP Address
```
host www.megacorpone.com
```
By default, the host command searches for an A record, but we can also query other fields, such as MX or TXT records, by specifying the record type in our query using the -t option.
```
host -t mx megacorpone.com
```
using **dnsrecon** to automate dns enumeration
```
dnsrecon -d megacorpone.com -t std
```
using **dnsenum** 
```
dnsenum megacorpone.com
```
on Windows Screen 
```
nslookup mail.megacorptwo.com

nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

## SMB Enumeration
```
enum4linux
```