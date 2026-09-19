# SSRFScope 0.3.0

محرك كشف SSRF عملي مبني بالكامل على مكتبة Python القياسية، ومخصص للاختبار المصرّح به داخل مختبرات الجامعة أو بيئات يملكها فريق الاختبار.

> **تنبيه أخلاقي:** لا تستخدم الأداة ضد أنظمة لا تملكها أو لا تملك تصريحاً مكتوباً لاختبارها. الإعدادات الافتراضية محافظة، ولا تفحص Cloud Metadata تلقائياً.

## المكونات

```text
ssrfscope.py          المحرك والأوامر الرئيسية
lab_server.py         مختبر SSRF محلي معزول
README.md             دليل الاستخدام
 tests/               اختبارات Unit Tests
```

لا توجد تبعيات خارجية. المتطلبات: Python 3.9 أو أحدث.

## لغة الأداة والتقرير

واجهة الأوامر والقائمة التفاعلية باللغة الإنجليزية، بينما يتم إنشاء التقرير HTML باللغة العربية حتى يكون مناسباً للتسليم الجامعي.

## الوضع التفاعلي والشعار

يمكن تشغيل الأداة بدون معاملات:

```bash
python3 ssrfscope.py
```

ستعرض الأداة شعار SSRFScope الملون (ANSI فقط) مع تنبيه authorization، ثم تطلب عنوان الموقع أو IP، وبعد ذلك تظهر قائمة. الألوان تتعطل تلقائياً عند non-TTY أو عند ضبط `NO_COLOR`، ويمكن تعطيلها صراحةً عبر `--no-color`. إذا أدخلت IP أو رابطاً بدون Query Parameter ثم اخترت Full scan، ستطلب الأداة منك تحديد مصدر الحقن: Parameter أو Header أو JSON أو Form أو Raw Request file. يجب أن يكون الهدف هو نقطة SSRF فعلية، وليس عنوان الخادم العام فقط.

مثال صحيح:

```text
http://host/fetch?url=x
```

ستظهر قائمة:

1. Discover inputs (محلي بلا شبكة)
2. Full scan
3. Focused probe
4. Deep scan (baseline-count=3 وworkers محدود)
5. OOB listener
6. Generate report
7. DNS lab
8. Change target
0. خروج

الشعار المستخدم في التقارير هو `1212.png` إن وجد، مع fallback إلى `logo.png`:

```text
1212.png
أو
logo.png
```

## أسلوب الأوامر

واجهة سطر الأوامر مصممة بأسلوب قريب من Nmap: أوامر واضحة، `--help` منظم، Target في الأمر، خيارات إخراج مختصرة، ونتائج مرتبة. لكنها ليست Port Scanner؛ يجب تحديد Endpoint ونقطة حقن SSRF.

```text
scan          فحص شامل لنقاط الحقن
probe         فحص مركّز
deep-audit    غلاف مضبوط لـ scan مع defaults محافظة وpayloads صريحة فقط
discover      عرض نقاط الإدخال المكتشفة محلياً دون إرسال HTTP/DNS/OOB
report        إنشاء تقرير HTML من JSON
oob           خادم OOB مستقل وإدارة الأحداث
dns-rebind    خادم DNS تعليمي محدود لعناوين المختبر
```

خيارات الإخراج المختصرة:

```text
-oJ FILE      حفظ JSON
-oH FILE      حفظ تقرير HTML عربي
-v            تشغيل السجل التفصيلي
--no-color    تعطيل ألوان ANSI (ويُحترم NO_COLOR وnon-TTY تلقائياً)
```

### Discover الآمن (لا شبكة)

يعرض `discover` نقاط الإدخال الموجودة في URL أو `--request-file` أو `--profile` أو `--body-json` أو `--body-form` فقط. لا ينشئ HTTP client ولا يرسل أي HTTP أو DNS أو OOB request، ولا يختار payloads تلقائياً. القيم الموجودة في Query URL تُخفى في الناتج، وتبقى أسماء الحقول فقط.

```bash
python3 ssrfscope.py discover \
  'http://127.0.0.1:8787/api/fetch?url=x&mode=preview' \
  --body-json '{"options":{"redirect":{"url":"x"}}}' \
  --body-form 'destination=x&mode=preview' \
  --json --no-color
```

`--all-request-headers` متاح مع `discover` و`scan`، لكنه لا يضيف تلقائياً `Authorization` أو `Cookie` أو `Content-Length` أو `Host` أو `Content-Type` أو `User-Agent` أو `Accept` أو `Transfer-Encoding`. إذا كان اختبار Header حساساً مصرحاً به، حدده صراحةً عبر `--header-target` ومرّر قيمته المقصودة يدوياً وفق سياسة المختبر. في `scan` و`probe` يجب أن تكون كل payloads المطلوبة explicit عبر `--payload`؛ لا يوجد randomized scan يوسّع الأهداف أو يرسل payloads غير محددة.

مثال:

```bash
python3 ssrfscope.py scan \\
  http://127.0.0.1:8787/fetch?url=x \\
  --param url \\
  --payload http://127.0.0.1:8788/ \\
  -oJ scan.json -oH scan.html
```

## التشغيل السريع في المختبر

شغّل المختبر:

```bash
python3 lab_server.py
```

الخدمات:

```text
التطبيق التجريبي:     http://127.0.0.1:8787
الخدمة الداخلية:      http://127.0.0.1:8788
جامع OOB في المختبر:  http://127.0.0.1:8789
```

ثم نفّذ فحص SSRF:

```bash
python3 ssrfscope.py scan \
  'http://127.0.0.1:8787/fetch?url=x' \
  --payload 'http://127.0.0.1:8788/' \
  --save first-scan.json
```

سيتم إنشاء التقرير تلقائياً:

```text
first-scan.json
first-scan.html
```

## فحص Parameters وHeaders

فحص Parameter محدد:

```bash
python3 ssrfscope.py probe \
  'https://authorized.example/fetch?url=https%3A%2F%2Fexample.org' \
  --param url \
  --payload 'http://127.0.0.1:8788/'
```

في `scan` يتم اكتشاف Query Parameters الموجودة في الرابط تلقائياً إذا لم تستخدم `--param`.

فحص Header مع Header ثابت للمصادقة:

```bash
python3 ssrfscope.py probe \
  'https://authorized.example/proxy' \
  --header-target X-Target-URL \
  --set-header 'Authorization=Bearer REDACTED' \
  --payload 'http://127.0.0.1:8788/'
```

لا تضع Tokens حقيقية داخل ملفات المشروع أو أوامر محفوظة في Git.

### deep-audit: فحص مضبوط بلا اكتشاف عشوائي

`deep-audit` ليس محركاً جديداً ولا يكرر منطق الفحص؛ هو alias آمن لمسار `scan` الحالي مع إعدادات محافظة: `baseline-count=3`، و`retries=1` لأخطاء الشبكة فقط، و`workers=2`، و`delay=0.25` ثانية، وtimeout، وحدود `max-body`/`max-headers`، وredaction مفعّل افتراضياً. لا ينشئ أهدافاً أو payloads عشوائياً، ولا يفحص metadata/cloud أو المنافذ أو يتجاوز ضوابط الوصول أو يستخرج credentials.

يجب تقديم URL أو `--request-file` لاحقاً، مع نقطة حقن صريحة أو مكتشفة من المصدر، و`--payload` أو `--oob-template` صريح. يمكن استخدام `--scope-host` كـ allowlist تطابق hostname حرفياً؛ عند وجودها يُرفض أي هدف خارج النطاق ولا يحدث DNS resolution للتحقق من النطاق.

خطة محلية بلا شبكة:

```bash
python3 ssrfscope.py deep-audit \
  'https://authorized.example/endpoint?url=PLACEHOLDER' \
  --param url --scope-host authorized.example --dry-run --json
```

تنفيذ مصرح به مع payload placeholder صريح:

```bash
python3 ssrfscope.py deep-audit \
  'https://authorized.example/endpoint?url=PLACEHOLDER' \
  --param url --scope-host authorized.example \
  --payload 'https://payload.example/PLACEHOLDER' \
  --save deep-audit.json -oH deep-audit.html
```

يدعم أيضاً `--header-target` و`--body-json`/`--body-json-field` و`--body-form`/`--body-form-field` و`--request-file`. في الوضع العادي يفشل الأمر إذا لم توجد payload صريحة؛ أما `--dry-run` فيطبع الخطة فقط ولا يرسل HTTP أو DNS أو OOB. يتضمن JSON وHTML النطاق، والإعدادات والمحاولات، وfindings، وevidence، وconfidence، والقيود، وعبارة صريحة بأن التحقق اليدوي مطلوب.

## JSON وForm Body

JSON top-level أو nested:

```bash
python3 ssrfscope.py probe \
  'http://127.0.0.1:8787/api/fetch' \
  --body-json '{"options":{"redirect":{"url":"x"}}}' \
  --body-json-field options.redirect.url \
  --method POST \
  --payload 'http://127.0.0.1:8788/'
```

في `scan` يمكن اكتشاف الحقول scalar تلقائياً:

```bash
python3 ssrfscope.py scan \
  'http://127.0.0.1:8787/api/fetch' \
  --body-json '{"url":"x","mode":"preview"}' \
  --method POST \
  --payload 'http://127.0.0.1:8788/'
```

Form:

```bash
python3 ssrfscope.py probe \
  'http://127.0.0.1:8787/form-fetch' \
  --body-form 'url=x&mode=preview' \
  --body-form-field url \
  --method POST \
  --payload 'http://127.0.0.1:8788/'
```

## استيراد HTTP Request من Burp أو ملف نصي

أنشئ ملفاً مثل `request.txt`:

```http
POST /api/fetch HTTP/1.1
Host: 127.0.0.1:8787
Content-Type: application/json
X-Lab-Header: demo

{"url":"x","mode":"preview"}
```

ثم شغّل:

```bash
python3 ssrfscope.py scan \
  --request-file request.txt \
  --all-request-headers \
  --payload 'http://127.0.0.1:8788/' \
  --save request-scan.json
```

يتم اكتشاف method وHost وContent-Type وBody وحقول JSON. Headers الحساسة مثل `Authorization` و`Cookie` لا تُحقن تلقائياً عند استخدام `--all-request-headers`؛ حددها يدوياً إذا كان الاختبار مصرحاً.

## Blind SSRF وOOB

### خادم OOB مستقل

في نافذة منفصلة:

```bash
python3 ssrfscope.py oob start \
  --bind 127.0.0.1 \
  --port 8790 \
  --events-file oob-events.json
```

نفّذ الفحص باستخدام callback:

```bash
python3 ssrfscope.py probe \
  'http://127.0.0.1:8787/fetch?url=x' \
  --param url \
  --oob-template 'http://127.0.0.1:8790/callback/{token}' \
  --save oob-scan.json
```

عرض الأحداث:

```bash
python3 ssrfscope.py oob events \
  --events-file oob-events.json \
  --pretty
```

مسح الأحداث:

```bash
python3 ssrfscope.py oob clear --events-file oob-events.json
```

يولّد SSRFScope Token مختلفاً لكل محاولة ويحفظه في `oob_token` و`payload_template` داخل JSON.

## DNS Rebinding التعليمي

هذه الميزة مخصصة لمختبر معزول فقط. الخادم يقبل عناوين private/loopback/reserved فقط، ولا يقبل IP عام عشوائي.

شغّل DNS server:

```bash
python3 ssrfscope.py dns-rebind start \
  --bind 127.0.0.1 \
  --port 53535 \
  --first-ip 198.51.100.10 \
  --second-ip 127.0.0.1 \
  --switch-after 1 \
  --ttl 1
```

اختبر تسلسل الإجابات:

```bash
python3 ssrfscope.py dns-rebind query example.test \
  --server 127.0.0.1 \
  --port 53535 \
  --count 3
```

الناتج المتوقع يكون قريباً من:

```json
{
  "answers": [
    "198.51.100.10",
    "127.0.0.1",
    "127.0.0.1"
  ]
}
```

هذه أداة تعليمية لشرح تغير DNS responses، وليست طريقة لتجاوز أنظمة خارج نطاق المختبر.

## التقارير واكتشاف النتائج الجديدة

بعد كل `scan` أو `probe` ينشئ البرنامج JSON وHTML تلقائياً. لتعطيل HTML:

```bash
--no-auto-report
```

إعادة إنشاء التقرير:

```bash
python3 ssrfscope.py report first-scan.json --output first-scan.html
```

### التقرير HTML التفصيلي والآمن

خيار `-oH/--report` في `scan` و`probe`، أو الأمر `report`، ينشئ تقريراً HTML تفصيلياً بشكل افتراضي. يعرض التقرير جدول ملخصاً بروابط داخلية إلى بطاقة مستقلة لكل attempt مصنف `interesting` أو `possible-ssrf`. تتضمن البطاقة نقطة الحقن، و`payload template`، و`severity`، و`confidence`، و`score`، والأسباب، وملخص الاستجابة (status وContent-Type والعنوان وطول body وSHA-256 وحالة الاقتطاع)، وملخص Baseline، إضافة إلى المنهجية والقيود.

يستخدم التقرير HTML escaping لكل القيم القادمة من نتائج الفحص. لا يعرض `body_preview` أو رؤوس الاستجابة الحساسة عندما تكون redaction مفعلة (وهو الوضع الافتراضي)، وتظل الرؤوس محدودة العدد وفق `--max-headers`. يمكن استخدام `--no-redact` فقط في مختبر مصرح به إذا احتجت إلى عرض هذه البيانات للمراجعة، مع اعتبار الملف الناتج حساساً. ويتضمن التقرير قسم remediation عام يوصي بـ allowlist للـ schemes/hosts/ports، ومنع private وlink-local وloopback بعد DNS resolution، وضبط redirects، وegress filtering، وtimeouts، وlogging الآمن.

إذا لم توجد findings، يعرض التقرير رسالة واضحة بدلاً من إنشاء بطاقات فارغة.

مقارنة فحصين:

```bash
python3 ssrfscope.py scan \
  'http://127.0.0.1:8787/fetch?url=x' \
  --param url \
  --payload 'http://127.0.0.1:8788/' \
  --save second-scan.json \
  --compare first-scan.json
```

يعرض التقرير:

- اكتشافات جديدة
- نتائج اختفت أو تم حلها
- نتائج زادت شدتها
- توقيعات جديدة ظهرت

هذه مقارنة بين فحصين، وليست قاعدة بيانات CVE أو ضماناً باكتشاف جميع أنواع الثغرات.

## المنهجية

لكل نقطة حقن يتم إنشاء Baseline باستخدام:

```text
ssrfscope-baseline
```

خيارات الضبط المحافظة الجديدة:

- `--baseline-count N` يكرر baseline (الافتراضي `2` في scan/probe و`3` في deep-audit) ويختار عينة ممثلة للمقارنة.
- `--retries N` يعيد المحاولة فقط لأخطاء الشبكة المؤقتة مع backoff؛ لا يعيد أي طلب بعد استجابة HTTP، بما في ذلك POST. ويمكن ضبط `--retry-backoff`.
- `--max-headers N` يحد عدد رؤوس الاستجابة المحتفظ بها، إلى جانب `--max-body` لحد حجم المحتوى.
- تُخفى الرؤوس الحساسة مثل `Authorization` و`Cookie` و`Set-Cookie` ومفاتيح/رموز شائعة افتراضياً في JSON والتقارير؛ كما لا يعرض التقرير التفصيلي `body_preview` عند تفعيل redaction. استخدم `--no-redact` فقط في مختبر مصرح.
- يضيف كل attempt قيمة `confidence` heuristic (ليست إثباتاً نهائياً) مشتقة من الأدلة الحالية.

ثم تتم مقارنة كل Payload مع Baseline باستخدام:

- تغيّر HTTP status
- توقيعات محتوى الخدمات الداخلية
- تغيّر body length
- تغيّر response time
- اختلاف أخطاء الشبكة
- عنوان الصفحة وContent-Type

التصنيفات:

```text
possible-ssrf   score >= 3
interesting     score = 2
inconclusive    score < 2
```

النتيجة Heuristic وتحتاج تحققاً يدوياً داخل النطاق المصرّح.

## Logs وProfiles

تفعيل السجل:

```bash
python3 ssrfscope.py probe URL \
  --param url \
  --payload 'http://127.0.0.1:8788/' \
  --log-file scan.log \
  --verbose
```

مثال Profile:

```json
{
  "headers": {
    "Authorization": "Bearer REDACTED"
  },
  "cookies": {
    "session": "REDACTED"
  }
}
```

تشغيله:

```bash
--profile profile.json
```

## الاختبارات

```bash
python3 -m py_compile ssrfscope.py lab_server.py
python3 -m unittest discover -s tests -v
```

## حدود الاستخدام

- لا توجد قراءة تلقائية لأسرار Cloud Metadata.
- لا يوجد تنفيذ أوامر عن بعد.
- لا يوجد استخراج Credentials.
- لا يتم اتباع Redirects افتراضياً.
- لا توجد تبعيات خارجية.
- لا تدّعي الأداة اكتشاف كل SSRF أو كل CVEs.
- لا تستخدم `--bind 0.0.0.0` إلا داخل شبكة مختبر معزولة وتحت تصريح واضح.

## المكتبات المستخدمة وأهميتها

المشروع مبني بالكامل على **Python Standard Library** ولا يحتاج إلى تثبيت مكتبات خارجية مثل `requests` أو `scapy`.

### مكتبات الواجهة والبيانات

| المكتبة | الاستخدام داخل المشروع | الأهمية والمستفيد |
|---|---|---|
| `argparse` | إنشاء أوامر `scan` و`probe` و`report` و`oob` و`dns-rebind` | تجعل الواجهة احترافية وقريبة من أدوات مثل Nmap، وتفيد المستخدم ومختبر الاختراق |
| `json` | قراءة JSON Body وProfiles وحفظ النتائج والأحداث | ضرورية لاختبار APIs الحديثة وإنتاج تقارير قابلة للمعالجة |
| `dataclasses` | تنظيم Target وResponse Snapshot | تجعل الكود أسهل في القراءة والصيانة |
| `typing` | Type Hints مثل `List` و`Dict` و`Optional` | تزيد وضوح الكود وتساعد الطالب أثناء المناقشة والتطوير |
| `datetime` | تسجيل وقت الفحص ووقت OOB callback | مهمة للتوثيق ومقارنة الفحوصات |
| `os` و`sys` | التعامل مع الملفات والمسارات ومتغيرات التشغيل وExit Codes | تساعد في تشغيل الأداة على Windows وLinux |
| `logging` | إنشاء ملفات Log مع `--verbose` و`--log-file` | تفيد في تتبع الطلبات والأخطاء أثناء الاختبار |

### مكتبات HTTP وتحليل الروابط

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `urllib.request` | إرسال GET وPOST وHTTPS Requests | محرك الإرسال الرئيسي بدون تبعيات خارجية |
| `urllib.error` | التقاط `HTTPError` و`URLError` ومشاكل الاتصال | أخطاء الشبكة قد تكون دليلاً على SSRF، كما تمنع توقف الأداة |
| `urllib.parse` | تحليل وتعديل Query Parameters وForm Body والروابط | تتيح حقن Payloads بطريقة صحيحة مع URL Encoding |
| `http.client` | التعامل مع أخطاء HTTP منخفضة المستوى | يحسن ثبات محرك الفحص |
| `ssl` | التحقق من TLS ودعم `--insecure` للمختبر | يسمح بفحص HTTPS وشهادات Self-Signed داخل بيئة اختبار |
| `http.server` | تشغيل OOB Listener وخدمات المختبر | يسمح باختبار Blind SSRF محلياً بدون خدمة خارجية |

### مكتبات التحليل والتزامن

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `re` | اكتشاف توقيعات Redis وElasticsearch وأخطاء الشبكة واستخراج HTML title | تقلل False Positives وتحوّل الاستجابة إلى Finding مفهومة |
| `hashlib` | إنشاء SHA-256 للاستجابة | مقارنة الاستجابات بدون حفظ Body كامل |
| `concurrent.futures` | تشغيل Payloads بالتوازي | يسرّع الفحص ويستفيد منه Pentesters وفرق AppSec |
| `threading` | تشغيل الخوادم وحماية ملف أحداث OOB | يسمح باستقبال أكثر من اتصال في الوقت نفسه |
| `time` | قياس زمن الاستجابة وتطبيق Delay | يساعد على كشف الفروقات الزمنية وتقليل ضغط الفحص |
| `uuid` | إنشاء OOB Token فريد لكل محاولة | يربط Callback بالـ Payload الصحيح |

### مكتبات التقرير والشعار

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `html` | عمل Escape للنصوص قبل وضعها في HTML | يحمي التقرير من HTML Injection عند عرض الاستجابات |
| `base64` | تضمين `logo.png` داخل تقرير HTML | يجعل التقرير مستقلاً ولا يحتاج إلى تحميل الشعار من الإنترنت |

### مكتبات DNS والسلامة

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `socket` | إنشاء UDP DNS Lab وإرسال DNS Queries | الأساس في تنفيذ DNS Rebinding التعليمي |
| `struct` | قراءة وإنشاء Binary DNS Packets | ضرورية للتعامل مع بنية بروتوكول DNS |
| `ipaddress` | التحقق من أن عناوين DNS Lab خاصة أو Loopback أو Reserved | تقلل خطر استخدام DNS Lab ضد عناوين عامة |

### مكتبات الاختبارات

| المكتبة | الاستخدام | الأهمية |
|---|---|---|
| `unittest` | Unit Tests للمحرك | يثبت أن الوظائف الأساسية تعمل قبل التسليم |
| `tempfile` | إنشاء ملفات مؤقتة لاختبار Raw Requests | يجعل الاختبارات معزولة وقابلة لإعادة التشغيل |
| `pathlib` | إدارة مسارات ملفات الاختبارات | يبسط التعامل مع الملفات على أنظمة التشغيل المختلفة |

## من يستفيد من SSRFScope؟

- **طلاب الأمن السيبراني:** لفهم SSRF وHTTP وOOB وDNS Rebinding.
- **مختبرو الاختراق:** لفحص Parameters وHeaders وAPIs داخل نطاق مصرح.
- **مطورو التطبيقات:** لاختبار Endpoints التي تستقبل URLs أو Webhooks.
- **فرق AppSec وDevSecOps:** لمقارنة نتائج الفحوصات وإدراجها في مراحل الاختبار.
- **فرق Cloud Security:** لاكتشاف مؤشرات الوصول غير المقصود إلى الخدمات الداخلية.
- **الجامعات والمدربون:** لعرض سيناريو عملي آمن بدون أسرار أو بيانات حقيقية.

## فائدة الأداة

تجمع SSRFScope في أداة واحدة:

```text
SSRF Detection
Response Heuristics
Blind SSRF / OOB
JSON وForm وHeaders
Raw HTTP Requests
DNS Rebinding Lab
Differential Findings
Arabic HTML Reports
Interactive Menu
```

الأداة ليست Port Scanner عاماً مثل Nmap؛ فهي تحتاج إلى Endpoint ونقطة حقن SSRF، لكنها تستخدم أسلوباً قريباً من Nmap في الأوامر والمساعدة وحفظ النتائج وعرض الحالة.
