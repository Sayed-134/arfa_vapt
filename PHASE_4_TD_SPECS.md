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

**Status:** Closed / Frozen
**Implementation:** commit b70e7b2 (merged via PR #18)

### Purpose

توسيع metadata المنظمة المرتبطة بكل payload بحيث تكون هوية وتصنيف
ومصدر الـpayload المستخدم قابلة للتتبع بشكل واضح، مع الحفاظ على
الـPayload contract الحالي.

### Problem

الـPayload الحالي يحتوي بالفعل على ID, Category, Value, وSource،
لكن لا توجد metadata منظمة إضافية كافية لوصف خصائص أو provenance
الـpayload عندما تكون هذه المعلومات متاحة من corpus structure.

### Required Behavior

1. الحفاظ على الحقول الحالية في models.Payload وعدم تغيير معناها.

2. إضافة metadata فقط عندما تكون مدعومة بوضوح من الـpayload
   corpus/loader.

3. metadata يجب أن تكون deterministic وقابلة للتتبع.

4. يجب أن تظل metadata مرتبطة بالـpayload المستخدم فعليًا.

5. لا يتم استنتاج metadata باستخدام heuristic أو AI.

6. عدم تغيير Payload.Value أو detector behavior بسبب metadata.

7. أي metadata غير متاحة بشكل موثوق تظل optional بدل اختراع قيمة.

### Pipeline Location

داخل مسار تحميل الـpayload في pkg/payloads/، مع تعديل الـPayload
representation فقط بالقدر الضروري لتمرير metadata المطلوبة، دون
إعادة تصميم detector/execution pipeline.

### Out of Scope

- تغيير محتوى payloads-database/.
- إعادة تصميم loader بالكامل.
- تغيير semantics أو قيمة الـpayload.
- AI/LLM للتصنيف.
- فرض استخراج Section أو Type إذا لم تكن قابلة للاستخراج بشكل موثوق.
- TD #16 corpus-level identity.

### Required Tests

- metadata صحيحة للـpayloadات التي تتوفر لها.
- الحفاظ على ID/Category/Value/Source.
- metadata deterministic.
- غياب metadata الاختيارية لا يكسر loading/execution.
- عدم تغيير detector behavior.
- regression tests للـpayload loading.

### Acceptance Criteria

يمكن تتبع الـpayload المستخدم وmetadata الخاصة به دون تغيير سلوك
scanner/detectors أو كسر الـPayload contract الحالي.

### Design Principle

> Metadata describes the payload; it does not change the payload.

---

## TD #8 — Global/cancellable rate limiter policy

**Status:** Closed / Frozen
**Implementation:** commit 2be0972 (merged via PR #23)
**Depends on:** TD #7 (مغلق)
**Blocks:** لا شيء

### Purpose

توحيد سياسة الـrate limiting على مستوى الـscan بحيث تكون كل الـprobe
requests خاضعة لسياسة واحدة واضحة، thread-safe، قابلة للإلغاء،
وقابلة للتتبع.

### Problem

`pkg/ratelimiter/Limiter` موجود، و`Wait(ctx context.Context)` موجود
بالفعل، والـscanner بيستدعيه من `rawProbe()`. لكن:

1. الـerror الراجع من `Wait(ctx)` بيتجاهل في `rawProbe` → لما الـcontext
   يتلغى، الـprobe بيكمل ويبعت HTTP request.
2. `Wait()` الحالي مجرد delay مستقل لكل caller — مش global serialized
   pacing حقيقي بين الـworkers.
3. `Feedback()` بيغيّر الـinterval أثناء وجود waiters — الـsemantics
   غير محددة.

### Required Behavior

1. **Single scan-wide limiter** — كل `Scanner` يستخدم limiter واحد
   مشترك بين كل الـworkers. مفيش limiter لكل worker أو detector.

2. **Global request pacing** — الـlimiter يحجز الإذن للـrequest على
   مستوى الـscan. نفس الـinput → نفس الـpacing. مفيش تجاوز المعدل
   بسبب workers متوازية.

3. **Cancellation propagation** — كل `Wait(ctx)` يحترم `ctx`.
   `rawProbe()` لازم يتحقق من الـerror الراجع من `Wait(ctx)` ويلغي
   الـprobe قبل أي HTTP request. `context.Canceled` /
   `context.DeadlineExceeded` بيت propagated لفوق بدون تحويل.

4. **Feedback semantics محددة** — `Feedback()` يؤثر على الـwaits
   الجديدة فقط. أي waiter بدأ بالفعل يحافظ على الـdelay المحسوب عند
   بدايته. مفيش burst ناتج عن تغيير الـinterval.

5. **Thread safety** — concurrent `Wait()` + `Feedback()` آمنين.
   مفيش race تحت `-race`.

6. **No leaks** — cancellation أثناء الـwait ما يسيّبش
   timers/goroutines معلقة.

7. **No signature change** — `Wait(ctx context.Context) error` يفضل
   زي ما هو. `Feedback()` يفضل زي ما هو (بس الـsemantics موثقة).

8. **لا تغيير في scanner accounting** — `Stats.Requests` زي ما هو.
   coverage / verification semantics زي ما هي. job scheduling order
   زي ما هو.

### Implementation Note

الـspec ما بيفرضش algorithm بعينه. لو التنفيذ اختار يحفظ الـinterval
القديم للـwaits الجارية، لازم يثبت بالاختبار إن الـglobal pacing policy
مش بتتجاوز.

### Pipeline Location

- `pkg/ratelimiter/limiter.go` — policy + feedback semantics.
- `pkg/scanner/scanner.go` — `rawProbe()` يتأكد من `Wait(ctx)` error
  قبل HTTP execution.

### Out of Scope

- إعادة تصميم adaptive concurrency.
- إعادة تصميم worker scheduler.
- تغيير `MaxJobs`, `MaxDuration`.
- تغيير endpoint ordering.
- تغيير detector/verification semantics.
- distributed rate limiting.
- per-domain scheduling.
- AI/heuristic rate selection.
- إعادة فتح أي TD مغلق.

### Required Tests

1. limiter واحد مشترك بين concurrent callers.
2. global pacing ما يسمحش بتجاوز policy بسبب workers متوازية.
3. cancellation أثناء `Wait()` → `context.Canceled`.
4. deadline أثناء `Wait()` → `context.DeadlineExceeded`.
5. `rawProbe()` ما يبعتش HTTP request بعد cancellation.
6. concurrent `Wait()` + `Feedback()` بدون race.
7. initial rate policy deterministic.
8. `Feedback()` عند 429/transport error يطبق policy محددة على waits
   الجديدة.
9. waits بدأت بالفعل ما بتتأثرش بتغيير الـinterval.
10. مفيش burst بعد `Feedback()` لأسوأ.
11. مفيش goroutine/timer leaks.
12. scanner-level test: initial/verification probes بيمروا من نفس
    الـlimiter.
13. `go test -race` على concurrent limiter usage.
14. regression للـscanner الحالي.

### Acceptance Criteria

- كل probe request في scan واحد خاضع لنفس global limiter.
- cancellation بتوقف limiter waits والطلبات اللاحقة.
- `rawProbe()` بيحترم `Wait(ctx)` error.
- مفيش races/leaks/bursts.
- adaptive concurrency منفصل عن rate limiting.
- verification/evidence/coverage semantics ما اتغيرتش.
- backward-compatible configuration.
- `go test ./...`, `go test -race ./...`, `go vet ./...`,
  `go build ./...` PASS.

### Design Principle

> One scan, one global request policy, one cancellable limiter.
> Feedback affects new waits only.

---

## TD #9 — Complete relevant probe request/response evidence

**Status:** Closed / Frozen
**Implementation:** commit 0d1c57e (merged via PR #26)
**Depends on:** TD #6, TD #16 (مغلقين)
**Blocks:** TD #13
**Shared:** redaction policy مع TD #15

### Purpose

توسيع structured evidence بحيث يكون الـprobe المرتبط بالـfinding قابل
للفهم والمراجعة وإعادة التحقق، مع redaction-safe fields وحدود واضحة
للحجم والحساسية.

### Problem

`models.Evidence` الحالي فيه `RequestMethod`, `RequestURL`,
`ResponseStatus`, `ResponseSnippet`, `ResponseHash`, `VerificationTrace`.
مفيش `RequestHeaders` ولا `ResponseHeaders` — والـcomment الحالي صريح
إنه deliberately مش بيحمل raw headers.

المطلوب: إضافة **additive** header evidence **مع redaction قبل دخولها
للـ`Evidence` contract** — مش نضيف raw ثم ننظف.

### Required Behavior

1. **Evidence finding-scoped** — evidence مرتبط بالـprobe اللي أدى
   للـfinding أو بالـverification. مفيش traffic archive.

2. **Request evidence (additive fields)** — method, canonical URL,
   relevant query params, relevant form/body params (لو لزم),
   sanitized request headers.

3. **Response evidence (additive fields)** — status, sanitized
   response headers, bounded body snippet, body length, full-body
   hash.

4. **Verification probes** — initial vs repeat vs control
   distinguishable. verification trace منفصل عن raw evidence.

5. **Redaction policy (shared مع TD #15)** — نفس shared redaction
   utility. sensitive headers/fields: `Authorization`, `Cookie`,
   `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization`, bearer/basic
   credentials، password-like fields. deterministic. headers بتتدخل
   `models.Evidence` بعد الـredaction.

6. **Bounded size** — explicit size limits للـrequest/response
   evidence. truncation deterministic + معلنة.

7. **No silent data loss** — لو حصل truncation → status/length/hash
   يفضلوا متاحين.

8. **No change to finding truth** — evidence مش بيغير
   `VerificationStatus`. مش بيرفع/ينزل confidence. مش بيعيد تشغيل
   detector.

9. **Backward compatibility** — `Evidence` الحالي يفضل readable.
   fields الجديدة additive/optional (omitempty). `arfa.scan/v1`
   يفضل صالح.

### Implementation Note

كلمة *relevant* لازم implementation يحددها بشكل deterministic،
والاختبارات تثبت القاعدة المستخدمة.

### Pipeline Location

- `pkg/models/` — additive evidence contract.
- `pkg/scanner/` — assembling evidence من `ProbeResult` مع redaction
  قبل الدخول.
- Redaction utility: shared package (يستخدمها TD #9 وTD #15).

### Out of Scope

- full traffic recording.
- proxy/MITM integration.
- OOB evidence.
- HAR capture.
- تغيير verification architecture.
- تغيير detector semantics.
- تغيير finding status/confidence.
- permanent evidence database.
- LLM redaction policy الخاصة بـTD #15 (لكن نفس الـutility).
- Knowledge Base/Zetsu.

### Required Tests

1. relevant request info محفوظة.
2. relevant response info محفوظة.
3. sensitive request headers redacted قبل التخزين.
4. sensitive response headers redacted.
5. body truncation deterministic.
6. body length محفوظ.
7. response hash للـfull body.
8. initial/repeat/control probes distinguishable.
9. large evidence bounded.
10. legacy evidence valid.
11. verification status/confidence unchanged.
12. JSON serialization regression.
13. concurrent evidence assembly آمن.
14. نفس redaction policy زي TD #15 (shared utility test).

### Acceptance Criteria

- finding عنده evidence كافي لفهم الـprobe.
- مفيش raw sensitive headers/values في الـevidence.
- redaction + truncation deterministic.
- verification semantics ما اتغيرتش.
- evidence additive/backward-compatible.
- مفيش traffic-capture subsystem جديد.
- existing tests PASS.

### Design Principle

> Capture enough evidence to reproduce understanding, not enough
> traffic to become a data store. Sanitize before storage, not after.

---

## TD #11 — IDOR authenticated principal/session context

**Status:** Closed / Frozen
**Implementation:** commit 1da9cb7 (merged via PR #31)
**Depends on:** Phase 3 (مغلق)
**Blocks:** لا شيء

### Purpose

إعطاء IDOR verification context واضح يربط كل probe بالـauthenticated
principal/session اللي نفذ الاختبار، بحيث اختلاف response وحده ما يبقاش
كافي لاعتبار الحالة IDOR.

### Problem

- الـscanner بيعمل IDOR-related findings، لكن مفيش context عن: مين
  الـprincipal؟ أي session/auth context؟ هل المقارنة بين نفس
  الـprincipal؟ هل الاختلاف authorization ولا application behavior؟
- مفيش CLI flag حالي لتوفير context زي ده.
- الـspec ده يعرّف **Auth Context Contract** أولاً، ويسيب اختيار
  الـCLI/config mechanism للـimplementation.

### Required Behavior

1. **Auth Context Contract** — الـcontract يمثل: principal identity
   (label/reference — مش secret)، session/auth context identity (safe
   reference — مش raw credentials)، ربط بين الـprobe والـcontext.
   الـcontract additive على `pkg/models`. **الـCLI/config mechanism
   مش مفروض في الـspec** — implementation يختار لاحقاً.

2. **No credential persistence** — passwords/tokens/cookies/secrets
   مش بتتدخل finding أو history raw. الـcontext بيستخدم
   references/labels آمنة.

3. **Same-principal comparison** — كل probe بيوضح الـprincipal
   المستخدم. اختلاف response وحده مش دليل على cross-principal failure.

4. **Cross-principal support** — architecture تسمح بمقارنة principal
   A vs B لما يتوفرا صراحة. من غير context كافي → `INCONCLUSIVE` أو
   `LIKELY`، مش `CONFIRMED`.

5. **Authorization boundaries** — مفيش bypass للـauthorization gate.
   مفيش اختراع credentials/sessions. الـcontext لازم ييجي من
   operator/test setup صريح.

6. **Evidence linkage** — finding/evidence بيحدد context identifier.
   مش بيخزن السر.

7. **Deterministic semantics** — نفس principal/context + نفس probe →
   نفس context identity. context identity مش معتمدة على raw secret
   text لو ممكن.

8. **No auto account creation.**

9. **No change to generic verification.**

### Pipeline Location

- IDOR-specific scanning/verification flow في `pkg/scanner`.
- additive context model في `pkg/models`.
- HTTP/session execution changes minimal ومحصورة في دعم الـcontext،
  من غير إعادة تصميم `pkg/httpclient`.

### Out of Scope

- authentication framework.
- session management system.
- credential vault / secrets manager.
- CSRF.
- account provisioning.
- OAuth/OIDC.
- generic authorization engine.
- إعادة تصميم HTTP client.
- إعادة تصميم verification architecture.
- autonomous privilege escalation.
- تغيير semantics findings تانية.

### Required Tests

1. principal context موجود عند IDOR probe.
2. session context identifier موجود بدون raw credentials.
3. same principal → same context identity.
4. different principals → distinguishable.
5. raw auth token مش في serialized evidence.
6. raw cookie مش في serialized evidence.
7. IDOR comparison records principal per probe.
8. insufficient context → no false `CONFIRMED`.
9. cross-principal comparison بتفرق authorized vs unauthorized لما
   contexts صريحة.
10. non-IDOR findings unchanged.
11. JSON compatibility.
12. race tests على concurrent IDOR context.

### Acceptance Criteria

- IDOR findings مرتبطة بوضوح بـprincipal/session context.
- مفيش auth secrets raw.
- response difference وحده مش `CONFIRMED`.
- cross-principal verification ممكن بس بـcontexts صريحة.
- authorization boundaries محفوظة.
- existing scanner/detector behavior unchanged خارج IDOR.
- tests PASS.

### Design Principle

> An IDOR claim must identify who accessed what, under which
> authorized session context, and what changed between principals.
> The contract comes before the CLI.

---

## TD #12 — History storage persistence/locking/retention

**Status:** Closed / Frozen
**Implementation:** commit 10c4e50 (merged via PR #33)
**Depends on:** لا شيء
**Blocks:** لا شيء
**Note:** يطوّر `pkg/db` الموجود، مش `pkg/history` جديد.

### Purpose

تطوير `pkg/db` history store الحالي إلى storage آمن في حالات التشغيل
المتكرر/المتوازي، مع atomic writes، locking، retention policy، وscan
identity واضحة.

### Problem

- `pkg/db` موجود وبيسجل `scan_history.json` عن طريق `st.Save(r)`.
- مفيش: atomic writes (ممكن partial/corrupt record لو العملية
  اتقتلت)، locking/concurrency safety (scanين متوازيين ممكن
  يتخانقوا)، retention policy (الملف بيكبر بلا حدود)، scan identity
  واضحة (احتمال collision).
- في نفس الوقت، **مش عايزين storage subsystem جديد** جانب `pkg/db`
  القديم.

### Required Behavior

1. **Evolution لـ`pkg/db`** — نفس `scan_history.json` (أو امتداد
   له). additive/compatible schema لو احتاج. مفيش migration لنظام
   جديد.

2. **Atomic writes** — الكتابة على temp file ثم rename. interruption
   ما يسيّبش canonical record نصف مكتوب.

3. **Concurrency safety** — concurrent scans ما يعملوش corruption.
   locking/serialization mechanism واضحة. readers ما يقرأوش partial
   records.

4. **Stable scan identity** — كل record له scan identifier واضح.
   مفيش overwrite بسبب filename collision.

5. **Retention policy** — configurable. deterministic. بالعدد و/أو
   العمر. مفيش unbounded growth.

6. **Failure handling** — storage error observable. scan result
   الأساسي ما يتغيرش بسبب history failure. مفيش silent success.

7. **Sensitive data boundary** — history بتستخدم structured scan
   result/evidence contracts. مفيش raw credentials/traffic. TD #9
   وTD #15 boundaries محفوظة.

8. **Local-first** — مفيش distributed dependency.

9. **Backward compatibility** — scan execution شغال حتى لو history
   معطلة/مش متاحة.

### Pipeline Location

- `pkg/db` — التطوير الأساسي.
- Integration بعد اكتمال scan result، مش في probe path.

### Out of Scope

- Knowledge Base/Zetsu.
- distributed database.
- cloud storage.
- multi-node locking.
- search/indexing.
- dashboard.
- audit/event sourcing.
- raw traffic archive.
- تغيير scanner execution semantics.
- تغيير finding/evidence contracts (إلا history ID الإضافي).

### Required Tests

1. single scan persists.
2. persisted record reload.
3. concurrent writers no corruption.
4. concurrent readers no partial reads.
5. atomic write failure ما يسيّبش corrupt canonical record.
6. unique scan IDs.
7. retention by count.
8. retention by age (لو implemented).
9. retention ما بتمسحش records أحدث.
10. storage dir init deterministic.
11. permission/write failure surfaced.
12. history disabled/unavailable ما يفسدش scan result.
13. `go test -race` concurrent read/write.
14. regression للـscan/report output.

### Acceptance Criteria

- scan history persistent ومحلي.
- concurrency مش بتعمل corruption/lost records.
- writes atomic.
- retention policy explicit + testable.
- storage failures observable.
- مفيش distributed dependency.
- history مش raw traffic store.
- existing scanner behavior intact.
- `go test ./...`, `go test -race ./...`, `go vet ./...`,
  `go build ./...` PASS.

### Design Principle

> Evolve the existing history store into a durable,
> concurrency-safe contract — without creating a second storage
> subsystem.

---

## TD #13 — Attack-chain detection beyond rule/co-occurrence heuristics

**Status:** Closed / Frozen
**Implementation:** commit f0b679d (merged via PR #36)
**Depends on:** TD #9 (evidence)
**Blocks:** لا شيء
**Note:** Python-only schema changes. `arfa.scan/v1` **مش** هيتغير.

### Purpose

تطوير attack-chain detection في Python AI Engine من co-occurrence
rules إلى relationships مدعومة بالـevidence والـscan structure.

### Problem

- `detect_attack_chains()` الحالي بيعتمد على category co-occurrence.
- `AttackChain` schema الحالي فيه: `title`, `description`,
  `chain_type`, `related_finding_ids`, `potential_impact`.
- مفيش `relationships` ولا `evidence_refs` — سنضيفهم additive في
  Python schema بس.

### Required Behavior

1. **Evidence-backed relationships** — كل chain عنده relationships
   قابلة للتفسير. كل relationship بيشير لـfinding IDs موجودة فعلاً.

2. **Explicit chain stages** — ordered stages: initial weakness →
   enabling condition → affected endpoint → impact.

3. **No category-only chain** — category A + category B لوحدهم مش
   كافيين.

4. **Endpoint relationship support** — same endpoint, related paths,
   shared parameter/object, shared evidence markers, principal/session
   context.

5. **Verification-aware** — `VerificationStatus` محفوظ.
   unverified/inconclusive مش بتتعامل كfacts. chain output بيوضح
   درجة evidence بدل ما يرفع لـ`CONFIRMED`.

6. **Deterministic core** — relationship extraction deterministic.
   same normalized findings → same chain output/order.

7. **AI optional, not authoritative** — LLM (لو استُخدم)
   للـnarrative/explanation فقط. مش بينشئ findings/facts. مش بيستبدل
   deterministic correlation. narrative بيتخزن منفصل في الـreport
   layer (مثلاً `attack_chain_narratives`)، مش داخل `AttackChain`.

8. **Provenance** — كل chain بيحدد: finding IDs, relationship/reason,
   source evidence, chain type.

9. **No exploitation.**

10. **Stable output** — ordering deterministic. dedup deterministic.

11. **Python-only schema change** — `AttackChain` additive fields في
    `ai-engine/schemas/common.py`. `arfa.scan/v1` مش بيتغير.

### Pipeline Location

- `ai-engine/correlation/endpoint_correlator.py` — relationship
  extraction + chain assembly.
- `ai-engine/schemas/common.py` — additive fields على `AttackChain`.
- `ARFAEngine.process()` بيستدعي بعد normalization/dedup/risk.

### Out of Scope

- autonomous exploitation.
- agentic execution loop.
- تغيير Go scanner findings.
- تغيير verification status.
- LLM-based vulnerability detection.
- arbitrary graph DB.
- external threat intel.
- automatic remediation.
- تغيير risk scoring semantics.
- `arfa.scan/v1` change.

### Required Tests

1. category co-occurrence alone → no chain.
2. valid explicit relationship → chain.
3. every chain references existing finding IDs.
4. missing finding reference → no chain.
5. verification status preserved.
6. inconclusive findings مش بتتحول لـconfirmed facts.
7. same input → same chains.
8. duplicate relationships deduplicated.
9. chain ordering deterministic.
10. endpoint relationship test.
11. parameter/object relationship test.
12. evidence provenance preserved.
13. empty findings → no chains.
14. existing endpoint correlation unchanged.
15. LLM unavailable → deterministic chain detection still works.
16. LLM narrative (لو استُخدم) موجود منفصل عن `AttackChain`، ومش
    بيغيّر أي fact.

### Acceptance Criteria

- chains مبنية على relationships/evidence، مش co-occurrence.
- كل chain له provenance واضح.
- مفيش invented facts.
- verification semantics محفوظة.
- output deterministic.
- LLM مش required.
- مفيش autonomous exploitation.
- `arfa.scan/v1` unchanged.
- existing Python tests + regression PASS.

### Design Principle

> A chain is a sequence of evidenced relationships, not a list of
> vulnerabilities that happen to coexist. LLM narrative is optional
> presentation, never a security fact.

---

## TD #15 — LLM Input/Output Redaction

**Status:** Ready for Implementation
**Depends on:** TD #9 (shared redaction utility)
**Blocks:** لا شيء

### Purpose

إنشاء redaction boundary واحدة حول الـLLM، بحيث secrets/sensitive
data ما توصلش للـmodel input، وأي sensitive content من الـoutput ما
يتسربش لـreports/downstream.

### Problem

- `LLMClient` في `ai-engine/llm/client.py` بيبعت prompt string مباشرة
  عبر `requests.post(.../api/generate)`.
- الـprompt ممكن يحتوي findings/evidence/URLs/tokens/cookies/
  credentials.
- `prompts.py` هو templates فقط، مش HTTP caller — فهو مش الـboundary.
- الـoutput لازم يتحط في الـreport من غير تسريب.

### Required Behavior

1. **Single enforcement boundary** — كل prompt بيعدي على redaction
   قبل `requests.post`. كل output بيعدي على redaction بعد الاستلام.
   أي LLM call جديد مستقبلاً لازم يعدي من `LLMClient`.

2. **Deterministic redaction** — patterns/rules صريحة. نفس input →
   نفس output. مفيش ML/LLM لتحديد ما يُredact.

3. **Sensitive categories** — `Authorization` headers/tokens.
   `Cookie`/session values. API keys. bearer/basic credentials.
   password-like fields. common secret/token patterns.

4. **Shared redaction policy مع TD #9** — نفس الـutility/القائمة.
   TD #9 = evidence safety. TD #15 = LLM boundary safety. الـTDs
   مستقلين وظيفياً.

5. **Preserve analytical utility** — مش بنحذف كل context. field
   names, categories, endpoint structure, status, non-sensitive
   evidence metadata تفضل متاحة. redaction minimal قدر الإمكان.

6. **Output redaction** — الـoutput يعدي على نفس الـredaction قبل
   التخزين/الـreport. secret-like content → `[REDACTED]`.

7. **No scanner fact mutation** — الـLLM output مش بيغير:
   `VerificationStatus`, `VerificationConfidence`, evidence, finding
   identity, scanner facts.

8. **Failure-safe** — لو redaction فشلت → مفيش إرسال raw data
   (fail-closed). نفس المبدأ للـoutput.

9. **Logging safety** — exceptions/logs ما تطبعش raw sensitive
   prompt/response.

10. **No secrets storage** — الـredaction layer مش secrets DB. مفيش
    raw retention لأغراض "restore".

11. **Endpoint agnostic** — local/remote LLM → نفس السياسة.

12. **Health check مستثنى** — `is_available()` (e.g. `/api/tags`)
    مش بيحمل user/security data → مش محتاج content-redaction pipeline.
    الـrule: أي call بيحمل security/user content يعدي من الـredactor.

### Pipeline Location

- `ai-engine/llm/client.py` — enforcement boundary.
- `prompts.py` — templates فقط.
- shared redaction utility — يستخدمها `LLMClient` وTD #9.

### Out of Scope

- encryption system.
- secrets manager / credential vault.
- network transport security redesign.
- replacing Ollama/LLM provider.
- تغيير Go evidence contracts.
- تغيير scanner findings.
- LLM-based security detection.
- prompt-injection research.
- automatic secret rotation.

### Required Tests

1. `Authorization` header redacted.
2. Bearer token redacted.
3. Cookie/session value redacted.
4. API-key-like values redacted.
5. password-like fields redacted.
6. secrets inside URLs/strings handled per rules.
7. non-sensitive security context preserved.
8. same input → same redacted output.
9. output containing secret-like data redacted.
10. raw prompt never reaches HTTP request after redaction failure.
11. exceptions don't leak raw prompt/output.
12. scanner verification fields cannot be changed by LLM output.
13. empty/no-secret input remains usable.
14. LLM unavailable → deterministic engine path still works.
15. `is_available()` health check doesn't go through
    content-redaction (ولا يحمل security data).
16. regression للـreport generation.
17. shared redaction utility tested independently + reused by TD #9.

### Acceptance Criteria

- مفيش raw sensitive scanner data بتوصل للـLLM.
- input/output redaction deterministic + testable.
- redaction failure → منع الإرسال (fail-closed).
- output redaction بتمنع تسريب secret للـreport/downstream.
- scanner facts مش قابلة للتغيير من LLM.
- شغالة مع local وremote endpoints.
- existing AI engine behavior functional لما مفيش sensitive data.
- Python tests + regression PASS.

### Design Principle

> The LLM may interpret security data, but it never becomes the
> trusted source of security facts or a path around the data-safety
> boundary. One boundary, one policy, shared with evidence safety.

---

## TD #16 — Payload corpus reproducibility/versioning

**Status:** Closed / Frozen
**Implementation:** commit 0b89a70 (merged via PR #20)

### Purpose

تحديد exact corpus state المستخدم في كل scan بحيث يمكن تتبع النتائج
وإعادة تفسيرها/reproduce من ناحية payload corpus.

### Problem

Payload.ID يحدد payload منفردًا، لكنه لا يحدد حالة الـcorpus كاملة
التي تم تحميلها واستخدامها أثناء الـscan.

### Required Behavior

1. إنشاء deterministic corpus identity/fingerprint يمثل exact corpus
   state المستخدم.

2. الـidentity يجب أن تعتمد على corpus state الفعلي، وليس على payload
   واحد.

3. نفس corpus state يجب أن ينتج نفس identity.

4. تغيير corpus state يجب أن ينتج identity مختلفة.

5. يجب ربط corpus identity بالـscan الذي استخدمه.

6. يجب أن تكون الـidentity قابلة للتسجيل والتتبع ضمن scan
   result/evidence context المناسب.

7. لا يتم تغيير محتوى الـcorpus كجزء من TD #16.

8. آلية إنشاء الـfingerprint يجب أن تكون deterministic وقابلة للاختبار.

### Pipeline Location

عند تحميل/تجهيز الـpayload corpus في pkg/payloads/، ثم تمرير corpus
identity إلى scan context/result بالحد الأدنى اللازم للتتبع.

### Out of Scope

- إنشاء payload database جديد.
- تعديل محتوى payloads-database/.
- إعادة تصميم payload selection.
- تغيير detector behavior.
- TD #6 payload-level metadata.
- Knowledge Base/Zetsu.
- إعادة تصميم scan history.

### Required Tests

- نفس corpus state → نفس fingerprint.
- تغيير corpus state → fingerprint مختلفة.
- ترتيب traversal غير المؤثر لا يغير fingerprint إذا كانت identity
  مبنية على corpus content.
- identity مرتبطة بالـscan.
- reproducibility test من corpus state معروف.
- regression tests للـpayload loading/execution.

### Acceptance Criteria

كل scan يمكن تحديد الـexact corpus state الذي استخدمه، والـidentity
deterministic وقابلة للتتبع، بدون تغيير payload content أو execution
behavior.

### Design Principle

> TD #6 identifies payload metadata; TD #16 identifies the exact
> corpus state used by the scan.


---

## TD #17 — Method-aware parameter selection in detectors

**Status:** Closed / Frozen
**Implementation:** commit 79e6695 (merged via PR #28)
**Depends on:** TD #2 (مغلق), TD #9 (مغلق)
**Blocks:** لا شيء
**Note:** `pkg/detectors` only. الـscanner سليم؛ الـbug في الـdetector layer.

### Purpose

جعل `pkg/detectors`'s `params(ep)` helper method-aware، بحيث تختار الـparameters
الصحيحة حسب الـendpoint method، بدل ما تستخدم GET-oriented fallback list
لأي POST endpoint.

### Problem

`params(ep)` في `pkg/detectors/detector.go` مش method-aware.

1. الـscanner (TD #2) بيسجّل POST endpoints بـ`FormParameters`، ويصفّر
   `ep.Parameters` عند بناء الـjob (في `walkJobs`).
2. الـdetector بيستدعي `params(ep)` → `len(ep.Parameters) == 0` لـPOST →
   بيرجع الـfallback list من 7 GET-oriented parameters.
3. الـdetector بيلاقي finding (من الـprobe الحقيقي)، وبيعمل **7 findings**
   بنفس الـprobe بس بـ`Parameter` labels وهمية.
4. النتيجة: findings بـparameter identity خاطئة → evidence مضلّل،
   coverage mislabeling.

**ملاحظة مهمة:** الـscanner نفسه **سليم**. `walkJobs` بتبعت الـjob الصح
(`ep2.Parameters = [param]` لـGET، `ep2.FormParameters = [param]` لـPOST)،
والـrawProbe بيبعت الـparam الصح. الـbug في الـdetector helper بس.

**الـfallback list موجودة أصلاً لسبب:** دعم GET endpoints اللي مفيهاش
parameters مكتشفة (legacy behavior من قبل TD #2). المفروض تفضل للـGET بس.

### Required Behavior

1. **`params(ep)` method-aware** — تاخد `ep.Method` في الحسبان.

2. **GET behavior محفوظ**
   - `ep.Parameters` موجودة → استخدامها.
   - `ep.Parameters` فاضية → الـfallback list الحالي.
   - **TD #5's noise filter يفضل شغال على الـfallback list زي ما هو.**

3. **POST behavior صحيح**
   - `ep.FormParameters` موجودة → استخدامها.
   - `ep.FormParameters` فاضية → **zero parameters** (مفيش fallback).

4. **لا fallback cross-method** — POST ما تستخدمش GET fallback list،
   والعكس.

5. **Parameter identity دقيقة** — الـfinding `Parameter` يطابق الـparameter
   اللي اختاره الـscanner وأرسله الـprobe.

6. **لا تغيير في detector semantics الأخرى** — XSS/SQLi/LFI/... matching
   logic، evidence checking، verification semantics، `inject()` helper —
   كلهم زي ما هو.

7. **لا تغيير في الـscanner** — `effectiveParams` و`walkJobs` مش
   هيتلمسوا.

8. **Shared `params(ep)` helper** — التعديل في الـhelper واحد، مفيش تكرار.

### Pipeline Location

- `pkg/detectors/detector.go` — `params(ep)` helper.
- `pkg/detectors/detectors.go` — 9 call sites (زي ما هي).
- Tests في `pkg/detectors/`.

### Out of Scope

- تغيير `pkg/scanner`.
- تغيير detector matching logic.
- تغيير verification.
- تغيير `models.Endpoint`.
- تغيير TD #5's fallback list نفسها.
- تغيير TD #9's evidence.
- AI/heuristics.
- إعادة فتح أي TD مغلق.

### Required Tests

1. GET + Parameters موجودة → `params()` ترجعها.
2. GET + Parameters فاضية → fallback list الحالي (7).
3. POST + FormParameters موجودة → `params()` ترجعها.
4. POST + FormParameters فاضية → 0 parameters.
5. POST ما تستخدمش GET fallback.
6. GET ما تستخدمش FormParameters.
7. finding `Parameter` يطابق الـparameter المرسل فعلاً.
8. POST job واحد → finding واحد بس.
9. GET regression — كل TD #1-#5 behavior محفوظ.
10. TD #5 noise filter لسه شغال على GET fallback.
11. XSS/SQLi/LFI detectors behavior محفوظ للـGET.
12. race/concurrency — مفيش مشاكل.
13. `go test ./...` PASS (مع الأخذ في الحسبان إن `pkg/scanner/td9_evidence_test.go`'s POST test هيتحوّل لـ"exactly 1" — regression متوقع نتيجة إصلاح الـbug، ويتم تعديله في TD #17 مش في TD #9).

### Acceptance Criteria

- `params(ep)` method-aware.
- POST ما تستخدمش GET fallback.
- Findings للـPOST بـparameter identity صحيحة.
- GET behavior محفوظ بالكامل (TD #1-#5).
- مفيش تغيير في detector semantics خارج الـparameter selection.
- `go test ./... -race -count=1` PASS.
- `./scripts/run_e2e_regression.sh` PASS.
- `pkg/scanner/td9_evidence_test.go`'s POST tests محدّثة لـ"exactly 1".

### Design Principle

> One parameter selection rule, method-aware: GET uses GET parameters,
> POST uses POST parameters, and neither falls back to the other.

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
