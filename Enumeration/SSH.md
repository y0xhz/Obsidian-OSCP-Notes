### id_rsa.pub
Public key used in authorized keys dir for login
### id_rsa
- Private key which can be directly used for login
	- can also be bruteforced using ssh2john (converts to hash) and hash can be cracked using john or hashcat.
change permission id_rsa
```
chmod 600 id_rsa
```
ssh with id_rsa
```
ssh -i id_rsa user@ip
```
- For Passwordless login add id_rsa.pub to authorized keys directory
- -o StrictHostKeyChecking=no (to avoid errors related to host key)