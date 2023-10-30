```
showmount -e IP
```
Make Directory to our Kali Machine
```
mkdir /mount/nfs
```
Connect Victim machine to our Kali machine
```
mount -t nfs IP:/pathshown /mnt/nfs
```
Permission Denied ?
https://blog.christophetd.fr/write-up-vulnix/
