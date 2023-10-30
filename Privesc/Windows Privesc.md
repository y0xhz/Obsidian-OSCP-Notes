Transfer the following files to shell before proceeding - winpeas.exe, accesschk.exe
**Run WinPEAS**

## Things to Check 
- [ ] Get-History
- [ ] (Get-PSReadlineOption).HistorySavePath
- [ ] $env:appkey
- [ ] Get-ChildItem -Directory -Recurse
- [ ] Username and Hostname
- [ ] Group memberships of the current user
- [ ] Existing users and groups
- [ ] Operating system, version and architecture
- [ ] Network information
- [ ] Installed applications
- [ ] Running processes

## OS Enumeration
```
systeminfo | findstr /B /C:"OSName" /C:"OSVersion" /C:"SystemType"
hostname  
echo %username%
```

## User Enumeration
```
whoami  
whoami /priv  
whoami /groups  
net user  
net user "username"  
net localgroup  
net localgroup"localgroupname"
```

## Network Enumeration
```
ipconfig
ipconfig /all
netstat -ano
route print
```

## Installed Applications
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname (32-bit)

Get-ItemProperty 
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname (64-bit)
```
**Note**: The above command results might be incomplete always check C:\Program Files and Downloads Folder

## Process Enumeration (to view running applications)
```
Get-Process  
Get-Process -Name notepad | Select-Object -ExpandProperty "Path"
```

## Mount Information
```
mountvol (to list all drives that are currently mounted)(no mount points might be interesting have a look at it)
```

## Hidden In Plainview
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue  

Get-ChildItem -Path C:\Users\ -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue (Modify path to your desired) 

Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue  

Get-ChildItem -Path "C:\" -Filter ".git" -Recurse -Force (to discover .git or any folder in c:\)

runas /user:offsec cmd (works only in gui/rdp)
```

## Service & Process Enumeration [[Service and Process Enumeration]] 