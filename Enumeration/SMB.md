If CME fails try SMBCLIENT, Use SMBMAP for access details
```
nmap --script smb-protocols IP
```
List all scripts that can be used in nmap
```
ls -l /usr/share/nmap/scripts/smb*
```
Login in Windows 
```
net view \\dc01 /all
```
### Enumerating SMB Shares
```
crackmapexecsmbip  
crackmapexecsmbip--shares  
crackmapexec smb ip -u '' -p ''  
```

```
enum4linux -a IP 
```
Look for shares (we need password try to find from any clue or method and use it to enumerate share)
```
smbmap -H IP
smbmap -H ip -u 'user' -p'pass'  
smbmap -H ip -u'' -p''  
smbmap -H ip -u''  
smbmap -H ip -s share_name  
smbclient -L //ip  
smbclient -L //ip/  
smbclient //ip/sharename  
smbclient -L //ip -N(Nopassword(SMBNullsession))  
smbclient --no-pass -L ip(nopass)  
smbclient -p 445 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
```
User -U in above commands to access specific user shares
#### Easy Way to Download ALL Files in SMB Shares
toggles recursion
```
recurse ON
```
doesn't prompt to download (y/n)
```
prompt OFF
```
Download all 
```
mget *
```

#### Groups.xml ?
```
gpp-decrypt "hash"
```
