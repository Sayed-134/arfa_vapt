# Phase 4 — Technical Debt Specifications

> **Purpose:** Implementation-level specifications for active Phase 4
> Technical Debt items.
>
> **Relationship to other documents:**
> - `ARFA_MASTER_CONTEXT.md` — roadmap and current state (what exists and its status).
> - `PHASE_4_TD_SPECS.md` (this file) — exact execution-level scope for each TD
>   before implementation begins.
> - Git / `main` — the actual source of truth for what has been implemented.
>
> **Rules:**
> 1. No TD is implemented before its specification is written and approved here.
> 2. Specifications are written one TD at a time — only when that TD's turn
>    comes up — not all at once.
> 3. After a TD is closed, its specification is retained here as a historical
>    implementation contract, with its `Status` updated to `Closed / Frozen`
>    and the implementation commit recorded.
> 4. Every specification follows the same shape: Purpose / Problem /
>    Required Behavior / Pipeline Location / Out of Scope / Required Tests /
>    Acceptance Criteria / Design Principle.

---

## TD #5 — Fallback Parameter Noise

**Status:** Closed / Frozen
**Implementation:** commit d8329ce (merged via PR #15)

### Purpose

تقليل scan work غير الضروري الناتج عن parameters التي يكتشفها الـcrawler
ولا تمثل عادةً مدخلات أمنية، مع الحفاظ على أي parameter غير معروف.

### Problem

الـcrawler قد يكتشف parameters مثل:

- "utm_source"
- "utm_medium"
- "utm_campaign"
- "utm_term"
- "utm_content"
- "cache_bust"
- "_t"

وقد تتحول هذه parameters إلى scan jobs تستهلك request budget ووقت التنفيذ
وcoverage slots دون قيمة أمنية واضحة.

### Required Behavior

1. **Known-noise list صريحة**
   - تعتمد عملية filtering على قائمة معروفة ومحددة من parameters.
   - القائمة الأولية تشمل الأسماء المذكورة أعلاه.

2. **Unknown parameters تُحفظ**
   - أي parameter غير موجود في known-noise rules لا يتم حذفه.

3. **لا يتم اعتبار parameter noise لمجرد أنه:**
   - رقمي
   - زمني
   - عشوائي
   - قصير أو طويل
   - متغير بين requests

4. **لا توجد smart heuristics**
   - لا ML
   - لا LLM
   - لا statistical inference
   - لا runtime guessing

5. **Deterministic behavior**
   - نفس input يجب أن ينتج نفس filtering result.

6. **Conservative fallback**
   - عند الشك، يُحافظ على الـparameter ولا يُفلتر.

### Pipeline Location

يتم تطبيق filtering داخل الـexisting endpoint/parameter processing flow،
قبل توليد scan work غير الضروري.

لا يغيّر TD #5:

- Endpoint Identity "(URL, Method)"
- URL Canonicalization
- Deterministic ordering
- Planner architecture
- Verification architecture

### Relationship with Fallback Parameter List

قائمة الـfallback parameters مثل:

"q", "id", "search", "page", "url"

ليست جزءاً من TD #5.

TD #5 تتعامل فقط مع parameters التي يكتشفها الـcrawler وتحدد known noise منها.

منطق fallback parameter guessing/selection هو concern منفصل ولا يدخل ضمن
هذه TD.

### Out of Scope

لا تشمل TD #5:

- Traffic Ingestion
- Headless Browser
- OOB
- Differential Analysis
- AI-based parameter classification
- تغيير Endpoint Identity
- تغيير URL Canonicalization
- إعادة فتح TD #1/#2/#3/#4
- تغيير أي contract مغلق في Phase 1–3 أو TD #7/#10/#14
- أي Future Feature

### Required Tests

يجب أن تغطي الاختبارات:

1. Known-noise parameter → filtered.
2. Unknown parameter → preserved.
3. Timestamp-looking parameter غير موجود في القائمة → preserved.
4. Numeric parameter → preserved.
5. نفس input → نفس output.
6. عدم حدوث regression في behavior الخاص بـTD #2 وTD #4.

### Acceptance Criteria

- Known noise يتم التعامل معه بشكل deterministic.
- Unknown parameters يتم الحفاظ عليها.
- لا توجد aggressive heuristics.
- لا تتأثر العقود والـTDs المغلقة.
- "go test ./..." ينجح.
- لا يتم إدخال أي Future Feature.

### Design Principle

«Filter only what is explicitly known as noise; preserve everything else.»

---

## TD #6 — Payload corpus structured metadata/versioning

**Purpose:** إضافة metadata منظمة للـpayload corpus.

**Required:** كل payload يبقى له metadata واضحة وقابلة للتتبع، مثل
المصدر/الفئة/النوع والمعلومات اللازمة لفهمه واستخدامه.

**الهدف:** معرفة payload المستخدم ومصدره وتصنيفه بدون تغيير detector
behavior.

**Out of Scope:** تغيير payload database نفسه، إعادة تصميم detectors،
أو إدخال AI في اختيار payloads.

**Status:** Context only — full specification required before implementation.

---

## TD #8 — Global/cancellable rate limiter policy

**Purpose:** توحيد سياسة الـrate limiting على مستوى الـscan بدل ما تكون
موزعة بشكل يسبب تجاوزات أو سلوك غير متوقع.

**Required:** limiter واحد/سياسة واضحة، قابلة للإلغاء مع الـscan
cancellation، deterministic وthread-safe.

**الهدف:** الـrate limit يكون فعليًا global على الـscan ويحترم
cancellation.

**Out of Scope:** تغيير adaptive concurrency أو إعادة تصميم scheduler،
إلا بالقدر الضروري لتطبيق السياسة.

**Status:** Context only — full specification required before implementation.

---

## TD #9 — Complete relevant probe request/response evidence

**Purpose:** جعل evidence المرتبط بالـprobe كامل بما يكفي لإعادة
فهم/مراجعة finding.

**Required:** حفظ relevant request/response information المرتبط
بالـprobe، مع redaction وحدود واضحة للحجم والحساسية.

**الهدف:** finding يبقى قابلًا للمراجعة وإعادة التحقق بدون تخزين raw
sensitive bodies بلا حدود.

**Out of Scope:** تخزين كل traffic، Traffic Ingestion، OOB، أو تغيير
Verification architecture.

**Status:** Context only — full specification required before implementation.

---

## TD #11 — IDOR authenticated principal/session context

**Purpose:** تحسين IDOR verification بحيث يكون عندنا context واضح
للـauthenticated principal/session.

**Required:** دعم principal/session context اللازم للمقارنة والتحقق
من IDOR، مع الحفاظ على authorization boundaries.

**الهدف:** عدم اعتبار اختلاف response وحده دليلًا كافيًا على IDOR.

**Out of Scope:** نظام authentication كامل، session management عام،
CSRF، أو إعادة تصميم HTTP layer.

**Status:** Context only — full specification required before implementation.

---

## TD #12 — History storage persistence/locking/retention

**Purpose:** جعل scan history persistent وآمن في حالات التشغيل
المتكرر/المتوازي.

**Required:** persistence واضحة + locking/concurrency safety +
retention policy محددة.

**الهدف:** منع corruption/races وضمان predictable history behavior.

**Out of Scope:** Knowledge Base/Zetsu، distributed database، أو إعادة
تصميم history كمنظومة مستقبلية كاملة.

**Status:** Context only — full specification required before implementation.

---

## TD #13 — Attack-chain detection beyond rule/co-occurrence heuristics

**Purpose:** تطوير correlation في Python من مجرد co-occurrence/rules
إلى attack-chain reasoning أكثر ارتباطًا بالأدلة.

**Required:** ربط findings/endpoints/relationships بطريقة
evidence-backed، مع provenance واضح وعدم اختراع facts.

**الهدف:** اكتشاف chains حقيقية من العلاقات الموجودة في scan data
بدل مجرد وجود vulnerabilities معًا.

**Out of Scope:** autonomous exploitation، agentic execution loop، أو
LLM يستبدل deterministic scanner facts.

**Status:** Context only — full specification required before implementation.

---

## TD #15 — LLM Input/Output Redaction

**Purpose:** منع تسريب secrets/sensitive data إلى الـLLM.

**Required:** redaction قبل إرسال البيانات للـLLM، ومعالجة output
أيضًا، بشكل deterministic قدر الإمكان وقابل للاختبار.

**الهدف:** الـLLM يشتغل على أقل قدر لازم من البيانات الحساسة.

**Out of Scope:** encryption system كامل، secrets manager، أو تغيير
Go evidence contracts.

**Status:** Context only — full specification required before implementation.

---

## TD #16 — Payload corpus reproducibility/versioning

**Purpose:** ضمان إمكانية معرفة وإعادة إنتاج الـpayload corpus
المستخدم في scan.

**Required:** تسجيل version/identity/source أو fingerprint مناسب
للـcorpus بحيث يمكن تحديد exact corpus state المستخدم.

**الهدف:** نفس الـscan يمكن تفسيره وإعادة إنتاجه من ناحية payload
source/version.

**Out of Scope:** بناء payload database جديد أو تغيير محتوى
الـcorpus نفسه.

**Status:** Context only — full specification required before implementation.

---

> **Note on TD #6 vs TD #16:**
> - **TD #6** = metadata داخل/حول الـpayload نفسه: ما هو هذا الـpayload؟
>   تصنيفه ومصدره وخصائصه.
> - **TD #16** = reproducibility للـcorpus كله: أي نسخة من corpus كانت
>   مستخدمة في هذا الـscan؟
>
> ده التقسيم اللي يمنع التداخل بينهم.

---

**End of PHASE_4_TD_SPECS.md**
