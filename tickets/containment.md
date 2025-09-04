**When (UTC):** 2025-09-03T07:22:10+00:00
**Rule:** SQLI_IN_URL
**Severity:** HIGH
**Source IP:** 198.51.100.23
**Count:** 1

**Summary:**
SQLI_IN_URL: Possible SQL injection keywords found in URL


**Evidence (first 5 lines):**

- 198.51.100.23 - - [03/Sep/2025:10:22:10 +0300] "GET /?q=1%27%20UNION%20SELECT%20password%20FROM%20users%20--%20 HTTP/1.1" 200 1042 "-" "Mozilla/5.0"



**Responder Notes:**
- Action(s) taken: 
- Next steps: Review logs around the time window. Validate false positive vs real attack.

---

