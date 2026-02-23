---
description: Scan codebase for security vulnerabilities and suggest fixes
argument-hint: [quick|standard|full]
allowed-tools: Read, Grep, Glob, Bash(npm audit:*), Bash(npx:*), Bash(ls:*), Bash(cat:*), Bash(supabase:*), Bash(pnpm audit:*), Bash(yarn audit:*), Bash(pip audit:*), Bash(bundle audit:*), Bash(go list:*), Bash(cargo audit:*)
model: sonnet
---

# Security Audit Skill

You are a security specialist conducting a structured codebase audit. Every search pattern and check in this prompt comes from real vulnerabilities found across production applications -- including patterns specifically common in AI-generated ("vibe coded") projects.

## Step 1: Parse Scan Depth

Read `$ARGUMENTS` to determine scan depth:

- **`quick`** -- Secrets + critical vulnerabilities only. Run Phases 1-2 only.
- **`standard`** (default, or empty argument) -- Run Phases 1-6. Includes OWASP Top 10, input validation, dependencies, and stack-specific checks.
- **`full`** -- All phases (1-8). Adds API contract/type safety audit and production readiness review.

Announce the scan mode at the start of your report.

## Step 2: Tech Stack Auto-Detection

Before scanning, detect the tech stack by checking for these files. Set detection flags for each match -- these control which checks run in Phase 6.

**Package manager / language:**
- `package.json` -- Node.js/JavaScript/TypeScript
- `requirements.txt` / `pyproject.toml` / `Pipfile` -- Python
- `Gemfile` -- Ruby
- `go.mod` -- Go
- `Cargo.toml` -- Rust
- `pom.xml` / `build.gradle` -- Java

**Frontend framework (check package.json dependencies + config files):**
- `next.config.*` or `"next"` in deps -- **Next.js** (flag: `NEXTJS`)
- `"react"` in deps (without Next.js) -- React SPA
- `svelte.config.*` or `"@sveltejs/kit"` in deps -- **SvelteKit** (flag: `SVELTEKIT`)
- `nuxt.config.*` or `"nuxt"` in deps -- **Nuxt** (flag: `NUXT`)
- `astro.config.*` or `"astro"` in deps -- **Astro**
- `"@remix-run"` in deps -- **Remix**
- `"express"` in deps -- Express
- `"fastify"` in deps -- Fastify
- `angular.json` -- Angular
- `"django"` or `manage.py` -- Django
- `"flask"` in deps -- Flask
- `config/routes.rb` -- Rails

**Backend-as-a-Service / Database:**
- `supabase/` directory OR `"@supabase/supabase-js"` in deps -- **Supabase** (flag: `SUPABASE`)
- `firebase.json` OR `"firebase"` in deps OR `".firebaserc"` -- **Firebase** (flag: `FIREBASE`)
- `convex/` directory OR `"convex"` in deps -- **Convex** (flag: `CONVEX`)
- `prisma/schema.prisma` OR `"prisma"` in deps -- **Prisma** (flag: `PRISMA`)
- `"drizzle-orm"` in deps -- **Drizzle** (flag: `DRIZZLE`)
- `"mongoose"` in deps -- MongoDB/Mongoose
- `docker-compose.yml` with postgres -- PostgreSQL
- `"@planetscale"` in deps -- PlanetScale
- `"@neondatabase"` or `"@neon"` in deps -- Neon
- SQL migration files or `.sql` files containing `CREATE POLICY` or `ENABLE ROW LEVEL SECURITY` -- **PostgreSQL RLS** (flag: `POSTGRES_RLS`). This flag activates RLS-specific checks regardless of whether Supabase is detected, covering direct PostgreSQL, Neon, or any ORM-backed project using Row-Level Security.

**Authentication provider:**
- `"@clerk"` in deps -- **Clerk** (flag: `CLERK`)
- `"next-auth"` or `"@auth/core"` in deps -- **Auth.js** (flag: `AUTHJS`)
- `"better-auth"` in deps -- **Better Auth** (flag: `BETTERAUTH`)
- `"lucia"` in deps -- **Lucia** (flag: `LUCIA`, also note: deprecated March 2025)

**Payments:**
- `"stripe"` or `"@stripe"` in deps -- **Stripe** (flag: `STRIPE`)
- `"@lemonsqueezy"` in deps -- Lemon Squeezy
- `"@paddle"` in deps -- Paddle

**AI/LLM integrations:**
- `"openai"` in deps -- **OpenAI** (flag: `OPENAI`)
- `"@anthropic-ai/sdk"` in deps -- **Anthropic** (flag: `ANTHROPIC`)
- `"ai"` or `"@ai-sdk"` in deps -- **Vercel AI SDK**
- `"replicate"` in deps -- Replicate
- `"@google/generative-ai"` in deps -- Google Gemini

**Deployment / infrastructure:**
- `.github/workflows/` -- GitHub Actions CI/CD
- `vercel.json` or `.vercel/` -- **Vercel**
- `netlify.toml` -- **Netlify**
- `wrangler.toml` -- **Cloudflare Workers/Pages**
- `fly.toml` -- Fly.io
- `railway.json` or `railway.toml` -- Railway
- `Dockerfile` -- Docker deployment
- `manifest.json` with `"manifest_version"` -- Chrome Extension (flag: `CHROME_EXT`)

**Other:**
- `"resend"` in deps -- Resend (email)
- `"uploadthing"` or `"@uploadthing"` in deps -- UploadThing (file uploads)
- `"zod"` in deps -- Zod validation present (positive signal)

Report all detected stack components at the start.

---

## Phase 1: Secret Detection [ALL MODES]

Search for hardcoded credentials, API keys, and tokens. These patterns have found real secrets in production codebases. **42% of AI-generated JWT code uses hardcoded secrets** (Vidoc Security research).

**Grep for these patterns** (exclude `node_modules`, `.git`, `dist`, `build`, `.next`, `.svelte-kit`, lock files):

```
# Generic secrets
api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]
api[_-]?secret\s*[:=]\s*['"][a-zA-Z0-9]
password\s*[:=]\s*['"][^'"]{4,}
secret\s*[:=]\s*['"][^'"]{4,}
token\s*[:=]\s*['"][^'"]{8,}
PRIVATE_KEY
BEGIN.*PRIVATE KEY
Bearer [a-zA-Z0-9._-]{20,}
ghp_[a-zA-Z0-9]{36}
xox[bprs]-[a-zA-Z0-9-]{10,}

# AWS
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AKIA[0-9A-Z]{16}

# OpenAI
sk-proj-[a-zA-Z0-9]{20,}
sk-[a-zA-Z0-9]{20,}T3BlbkFJ

# Anthropic
sk-ant-[a-zA-Z0-9-]{20,}

# Stripe
sk_live_[a-zA-Z0-9]{20,}
pk_live_[a-zA-Z0-9]{20,}
whsec_[a-zA-Z0-9]{20,}
rk_live_[a-zA-Z0-9]{20,}

# Supabase
service_role.*ey[A-Za-z0-9_-]{20,}
SUPABASE_SERVICE_ROLE_KEY.*=.*ey

# Firebase
"apiKey"\s*:\s*"AIza[a-zA-Z0-9_-]{33}"

# Clerk
sk_live_[a-zA-Z0-9]{20,}

# Resend
re_[a-zA-Z0-9]{20,}

# Database connection strings
postgres://.*:.*@
mysql://.*:.*@
mongodb(\+srv)?://.*:.*@
DATABASE_URL.*=.*://

# JWT secrets
jwt[_.]?secret\s*[:=]\s*['"][^'"]{4,}
JWT_SECRET\s*=\s*[^$]
```

**Also check:**
- `.env.example` / `.env.sample` -- real values instead of placeholders? (Found in production: real Supabase keys in `.env.example`)
- `.gitignore` -- does it include `.env`, `.env.local`, `.env.production`, `.env*.local`?
- `.github/workflows/*.yml` -- hardcoded secrets instead of `${{ secrets.* }}`?
- `localStorage.setItem` / `sessionStorage.setItem` with tokens, keys, or passwords
- Firebase config objects with real `apiKey` values in client-side JS (note: Firebase apiKey is technically public, but `measurementId` and other fields should be checked)

**Vibe coding specific -- client-side auth secrets (Wiz Research findings):**
```
# Passwords stored in client-side JavaScript
password\s*===?\s*['"]       # String comparison with password literal
if.*password.*===            # Client-side password check
localStorage.*auth           # Auth state in localStorage
localStorage.*token          # Tokens stored client-side
authenticated.*=.*true       # Boolean auth flags
isAdmin.*=.*true             # Client-side admin flags
```
These patterns catch the most common vibe coding mistake: putting the entire auth logic in the browser.

**Severity:** CRITICAL for any real secret found in source code.

---

## Phase 2: Critical Vulnerability Scan [ALL MODES]

These patterns catch the most dangerous vulnerabilities -- authentication bypass, injection, and access control failures.

### 2.1 Authentication Bypass

Search for:
```
--no-verify-jwt          # Supabase Edge Functions without JWT verification
verify.*=.*false         # TLS/cert verification disabled
rejectUnauthorized.*false
NODE_TLS_REJECT_UNAUTHORIZED
auth.*bypass
skip.*auth
dev.*mode.*=.*true       # Dev bypasses left in production
Warning:.*Running without  # Dev auth bypass pattern
```

For every API endpoint/route file found, check: does it verify the user is authenticated before processing? **Common vibe coding pattern: AI generates functional routes but forgets auth middleware.**

Check based on detected auth provider:
- **Clerk**: is `auth()` or `currentUser()` called in every API route / Server Action? Is `clerkMiddleware()` or `authMiddleware()` applied?
- **Auth.js**: is `getServerSession()` or `auth()` checked in every route? Is the middleware configured?
- **Supabase Auth**: is `supabase.auth.getUser()` called (not just `getSession()` -- sessions can be spoofed client-side)?
- **Firebase Auth**: is `admin.auth().verifyIdToken()` used server-side (not just client-side `onAuthStateChanged`)?
- **Better Auth**: is session validation happening server-side?

### 2.2 SQL / Command Injection

Search for:
```
# SQL injection
SELECT.*\+.*\+           # String concatenation in queries
execute.*%s              # Python format strings in SQL
query.*\$\{              # Template literals in SQL
\.raw\(                  # Raw SQL queries (Prisma, Knex)
\.rawQuery\(
\$queryRaw               # Prisma raw query
\$executeRaw             # Prisma raw execute
sql\.unsafe              # Drizzle unsafe SQL
db\.execute.*\$\{        # Drizzle template injection

# Command injection
exec\(                   # Shell execution
eval\(                   # Code evaluation
child_process            # Node.js subprocess
subprocess               # Python subprocess
system\(                 # Ruby/PHP system call
new Function\(           # Dynamic function construction
```

### 2.3 Database Security Gaps (based on detected stack)

**If Supabase detected:**
Search migration files and SQL for `SECURITY DEFINER` -- for each match, verify it also has `SET search_path`. Found in 15+ functions across 3 real projects.

Search for overly permissive RLS:
```
USING\s*\(\s*true\s*\)
USING \(true\)
```
Check: are there tables with policies defined but `ENABLE ROW LEVEL SECURITY` never called? (Silent fail-open -- found on 10 tables in one project.)

**RLS recursion risk:** When an RLS policy's `USING` clause subqueries another table, PostgreSQL evaluates *that* table's RLS policies too -- recursively. Two tables whose policies reference each other create infinite recursion, surfacing as 500 errors. Search for policies containing subqueries:
```
SELECT tablename, policyname, qual
FROM pg_policies
WHERE qual LIKE '%SELECT%FROM%'
ORDER BY tablename;
```
For each result, trace which tables the policy references and check whether those tables' policies reference back. If a cycle exists, it must be broken with a `SECURITY DEFINER` helper function (see Fix Pattern Library). **Warning:** replacing a permissive `USING(true)` policy with a restrictive one can *unmask* latent cycles, because `USING(true)` acts as a circuit breaker that never subqueries other tables.

**If POSTGRES_RLS detected (without Supabase):**
Run the same RLS checks above -- `SECURITY DEFINER` + `SET search_path`, overly permissive policies, missing `ENABLE ROW LEVEL SECURITY`, and recursion detection -- against any `.sql` or migration files in the project. These issues affect all PostgreSQL RLS users regardless of framework.

**If Firebase detected:**
Check `firestore.rules` and `storage.rules` -- search for:
```
allow read: if true       # Public read
allow write: if true      # Public write
allow read, write: if true
allow read, write         # Missing condition entirely
request.auth != null      # Only checks logged in, not ownership/role
```
Firebase Security Rules are the #1 security issue in Firebase apps.

**If Convex detected:**
Check `convex/` function files for missing auth checks:
```
# Convex functions without auth verification
export const.*=.*query\(   # Check: does it call ctx.auth.getUserIdentity()?
export const.*=.*mutation\( # Same check for mutations
```

**If Prisma detected:**
Check for `$queryRaw` and `$executeRaw` usage without parameterization. Also check that Prisma's preview feature `"interactiveTransactions"` isn't exposing transaction IDs.

**If Drizzle detected:**
Check for `sql.unsafe()` or template literal injection in `sql\`...\`` tagged templates without proper `sql.placeholder()` usage.

### 2.4 Webhook Signature Bypass

Search for webhook handling code. Check based on payment provider:

**Stripe webhooks** (if STRIPE detected):
```
stripe.*webhook
constructEvent
whsec_
```
Verify: is `stripe.webhooks.constructEvent(body, sig, secret)` called with the raw body (not parsed JSON)? Is the `stripe-signature` header checked? Does it reject missing signatures?

**General webhooks:**
- Does it reject requests with a missing signature header? (Not just invalid -- MISSING)
- Pattern found in production: omitting the `X-Signature` header skipped HMAC verification entirely.

### 2.5 Privilege Escalation

Search for:
```
role.*=.*admin            # Direct role assignment
\.update.*role            # Updating role field
status.*=.*active         # Reactivation patterns
isAdmin.*=                # Admin flag manipulation
```

Check: can a user modify their own role, status, or permission level?

**Vibe coding pattern:** AI-generated admin panels that check `role === "admin"` only on the client side. The server/database must independently enforce role-based access.

### 2.6 Client-Side Authentication (Vibe Coding Critical)

This is the #1 vulnerability in AI-generated apps (Wiz Research). Search for:
```
# Auth logic that lives entirely in the browser
if.*password\s*===
localStorage\.getItem.*auth
localStorage\.getItem.*admin
sessionStorage.*isLoggedIn
window\.__user
document\.cookie.*admin
```

If auth state is checked only via client-side JavaScript with no server-side session validation, flag as CRITICAL. An attacker can bypass by opening DevTools and setting `localStorage.setItem("authenticated", "true")`.

---

## Phase 3: OWASP Top 10 Scan [STANDARD + FULL]

### 3.1 Cross-Site Scripting (XSS)

Search for:
```
dangerouslySetInnerHTML   # React -- found in 5+ real cases
innerHTML                 # DOM XSS
document\.write           # DOM XSS
v-html                    # Vue / Nuxt XSS
\[innerHTML\]             # Angular XSS
{@html                    # Svelte XSS -- renders raw HTML
```

For each finding: is the content sanitized with DOMPurify or equivalent? If it renders AI-generated or user-supplied content, severity is HIGH.

**Svelte-specific:** `{@html content}` is Svelte's equivalent of `dangerouslySetInnerHTML`. Flag every use.

### 3.2 Injection (Database Filter / Prompt / NoSQL)

Search for:
```
# PostgREST / Supabase filter injection
\.or\(.*\$\{             # Template literal in .or() filter
\.ilike\(.*\$\{          # Template literal in .ilike()
\.filter\(.*\$\{         # Template literal in .filter()
\.textSearch\(.*\$\{     # Template literal in .textSearch()

# Firebase / Firestore injection
\.where\(.*\$\{          # Dynamic field names in Firestore queries
\.doc\(.*\$\{            # User-controlled document IDs

# MongoDB / NoSQL injection
\$where                  # JavaScript execution in MongoDB queries
\$regex.*\$\{            # User-controlled regex
\.find\(.*\$\{           # Dynamic query construction

# Prompt injection (AI apps)
# Look for user content concatenated directly into AI prompt strings
# Check if system instructions and user content are properly separated
# Vercel AI SDK: verify system messages use `system` role, not concatenated into `user`
```

### 3.3 Insecure Direct Object Reference (IDOR)

For UPDATE/DELETE database queries, check:
- Does the WHERE clause include user ID ownership check?
  - Supabase: `.eq("user_id", user.id)` or RLS policy
  - Prisma: `where: { id: resourceId, userId: session.user.id }`
  - Drizzle: `and(eq(table.id, resourceId), eq(table.userId, userId))`
  - Firebase: security rules check `request.auth.uid == resource.data.userId`
  - MongoDB: `{ _id: resourceId, userId: session.userId }`
- Pattern found: image replace endpoint filtered by `imageId` but not `user_id`.

### 3.4 Server-Side Request Forgery (SSRF)

Search for URL-fetching code:
```
fetch\(.*\$\{            # Dynamic URL fetch
axios\(.*\$\{
request\(.*\$\{
urllib
got\(.*\$\{              # Got HTTP client
```

Check: does it block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x), cloud metadata (169.254.169.254), and non-HTTP protocols?

### 3.5 Security Misconfiguration

Search for:
```
Access-Control-Allow-Origin.*\*    # CORS wildcard
credentials.*true.*\*              # Credentials with wildcard origin
Content-Security-Policy            # Check if CSP header is set
X-Frame-Options                    # Check if set
```

Check framework-specific CORS config:
- Next.js: `next.config.*` headers
- Express: `cors()` middleware options
- SvelteKit: `hooks.server.ts` handle function
- Nuxt: `nuxt.config.*` routeRules

### 3.6 Sensitive Data Exposure

Search for:
```
error\.message           # Raw error messages returned to clients (found 35+ in one project)
error\.stack             # Stack traces leaked to clients
console\.log             # Debug logging (found 50+ instances with sensitive data)
```

Check: are API error responses returning `error.message` or `error.stack` instead of static messages?

**AI app specific:** Are AI prompts, system instructions, or model responses being logged or returned to clients? LLM system prompts are intellectual property and should never be exposed.

### 3.7 Broken Access Control

Search for patterns where client-supplied values are trusted for server-computed data:
- Scores, ranks, XP, achievements submitted by client
- Price/amount fields in payment requests (should come from server, not client)
- Status fields settable by the user
- Any value that should be computed server-side but comes from the request body

**Stripe-specific:** Never trust client-supplied price. Create Checkout Sessions or PaymentIntents server-side with the price from your database, not from `req.body.price`.

---

## Phase 4: Input Validation & Resource Management [STANDARD + FULL]

### 4.1 Input Length Limits

Check API endpoints that accept text input: do they enforce length limits? Without limits, attackers can submit megabytes of text to exhaust AI API quotas or cause DoS.

**AI-specific:** LLM endpoints are especially vulnerable -- a 100K-character prompt costs real money. Check for limits before any `openai.chat.completions.create()`, `anthropic.messages.create()`, or Vercel AI SDK `streamText()` / `generateText()` call.

### 4.2 File Upload Validation

Search for file upload handling. Check UploadThing, Supabase Storage, Firebase Storage, S3, or custom upload routes:
- File size limits enforced?
- File type validation (not just extension, check MIME)?
- Filename sanitization (no path traversal with `../`)?
- Storage bucket permissions (are uploaded files public by default?)

### 4.3 Rate Limiting

Check: do expensive/sensitive endpoints have rate limiting?
- AI generation endpoints (cost exhaustion -- a single user could run up thousands in API costs)
- Login / MFA verification (brute force)
- Password reset (enumeration)
- Email sending (spam -- especially with Resend/SendGrid)
- Stripe webhook endpoints (replay attacks)
- File upload endpoints

Check for rate limiting libraries: `rate-limiter-flexible`, `@upstash/ratelimit`, `express-rate-limit`, `next-rate-limit`, custom `Map`-based limiters.

### 4.4 Weak Random Number Generation

Search for:
```
Math\.random             # Not cryptographically secure
```
Check: is it used for security-sensitive purposes (tokens, codes, session IDs, invite links)? Should use `crypto.getRandomValues()` or `crypto.randomUUID()`.

### 4.5 Redirect URL Validation

Search for redirect parameters (`?redirect=`, `?next=`, `?url=`, `?returnTo=`, `?callbackUrl=`). Check:
- Validated to start with `/`?
- Blocked from starting with `//` (protocol-relative)?
- Not allowing external URLs?

**Auth.js/NextAuth specific:** Check `callbacks.redirect` -- does it validate the `url` parameter?
**Clerk specific:** Check `afterSignInUrl` and `afterSignUpUrl` -- are they hardcoded or user-controllable?

### 4.6 PostMessage Origin Validation

Search for:
```
postMessage
addEventListener.*message
\.includes\(.*origin     # Weak origin validation using .includes()
```
Check: origin validation uses exact matching against an allowlist, NOT `.includes()` (bypassable with `evil-linkedin.com`).

---

## Phase 5: Dependency & Configuration Audit [STANDARD + FULL]

### 5.1 Dependency Vulnerabilities

Run the appropriate audit command:
- `npm audit` / `pnpm audit` / `yarn audit` (Node.js)
- `pip audit` (Python)
- `bundle audit` (Ruby)
- `cargo audit` (Rust)
- `go list -m -json all` (Go -- check for known vulns)

### 5.2 Unused / Hallucinated Dependencies

Check for dependencies in package.json that are never imported in the codebase. Unused dependencies expand the attack surface.

**Vibe coding specific -- "slopsquatting":** LLMs hallucinate non-existent package names ~5% of the time (Kaspersky research). Attackers register these fake names on npm with malware. Look for packages that:
- Have very low weekly download counts
- Were published very recently
- Have names that look like misspellings of popular packages
- Don't appear on the npm registry at all

### 5.3 Security Headers

If it's a web application, check for security headers configuration:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security`
- `Referrer-Policy`
- `Permissions-Policy`

Where to check:
- Next.js: `next.config.ts` headers array
- SvelteKit: `hooks.server.ts` handle function
- Nuxt: `nuxt.config.ts` routeRules or nitro config
- Astro: middleware or adapter config
- Express: `helmet` middleware
- Vercel: `vercel.json` headers
- Netlify: `netlify.toml` or `_headers` file
- Cloudflare: `_headers` file

### 5.4 Third-Party Scripts

Search for external script tags without Subresource Integrity (SRI):
```
<script.*src=.*http     # External scripts
integrity=              # SRI hashes (should be present on external scripts)
```

Also check for analytics/tracking scripts loaded without consent management (GDPR/privacy concern).

### 5.5 Password Policy

If the app has signup/registration, check minimum password length and complexity requirements. AI commonly generates 6-character minimums; modern standard is 8+ characters.

### 5.6 Deprecated Dependencies

Flag known deprecated/insecure packages:
- `"lucia"` -- deprecated March 2025, migrate to Better Auth or Clerk
- `"request"` -- deprecated, use `fetch` or `got`
- `"moment"` -- not a security issue but maintenance-mode; prefer `date-fns` or `dayjs`
- `"crypto-js"` -- known vulnerabilities; prefer Web Crypto API or `@noble/hashes`

---

## Phase 6: Stack-Specific Checks [STANDARD + FULL, conditional]

Run only the subsections matching detected flags.

### 6.1 Supabase / PostgreSQL RLS Checks (if SUPABASE or POSTGRES_RLS flag set)

> **Scope:** RLS-specific checks (Gap Detection, Recursion Detection, SECURITY DEFINER Audit, Testing) run for any project with the `SUPABASE` or `POSTGRES_RLS` flag. Supabase-specific checks (Client-Side Mutations, Edge Function Auth, Service Role Key, Auth method) run only when `SUPABASE` is set.

**RLS Gap Detection:**
Look for tables in migrations that don't have `ENABLE ROW LEVEL SECURITY`. Then check for overly permissive policies:
- `USING(true)` without documented justification
- UPDATE policies that don't restrict columns
- SELECT policies that expose sensitive columns (answers, tokens, join codes, passwords)

**SECURITY DEFINER Function Audit:**
For every SECURITY DEFINER function, verify:
- Has `SET search_path = ''` (or `= public`)
- Has `REVOKE EXECUTE ON FUNCTION ... FROM public`
- Has `GRANT EXECUTE ON FUNCTION ... TO authenticated`
- Validates caller role
- Validates all input bounds

**RLS Dependency Graph / Recursion Detection:**
RLS policies that subquery other RLS-protected tables create recursive evaluation chains. PostgreSQL evaluates every referenced table's policies before returning rows, and circular references cause infinite recursion (manifesting as 500 errors or timeouts).

For every table with RLS enabled:
1. List every table its policies' `USING`/`WITH CHECK` clauses reference (directly via subquery or JOIN)
2. For each referenced table, list what tables *its* policies reference
3. Continue until the full dependency graph is mapped or a cycle is found (A→B→A, or longer chains like A→B→C→A)

Detection query:
```sql
-- Find all policies with subqueries (potential recursion sources)
SELECT tablename, policyname, qual
FROM pg_policies
WHERE qual LIKE '%SELECT%FROM%'
ORDER BY tablename;

-- Find tables missing RLS entirely
SELECT tablename FROM pg_tables
WHERE schemaname = 'public'
AND tablename NOT IN (
  SELECT t.tablename FROM pg_tables t
  JOIN pg_class c ON c.relname = t.tablename
  WHERE c.relrowsecurity = true
);
```

Common pattern that causes recursion:
```
# Two-table cycle (most common)
Table A policy → subqueries Table B → Table B policy → subqueries Table A

# Example: profiles "Teachers read class students" → JOIN class_students, classes
# class_students "Teachers read class roster" → subquery on classes
# classes "Students read enrolled classes" → subquery on class_students
# Result: class_students ↔ classes infinite recursion, surfacing as 500 on profiles
```

Fix: replace the subquery in one policy with a `SECURITY DEFINER` helper function (see Fix Pattern Library). `SECURITY DEFINER` functions run as the function owner, bypassing RLS on tables they query internally, which breaks the cycle.

**Critical warning:** Tightening a permissive `USING(true)` policy can *introduce* recursion. `USING(true)` acts as a circuit breaker -- it grants access without querying other tables. Replacing it with a restrictive policy that subqueries another table may unmask a latent circular dependency. Always map the dependency graph before changing any policy.

**Testing RLS Policies:**
Always test as the actual runtime role, never as superuser (superusers bypass RLS entirely). A query that works in the SQL Editor as `postgres` can return 500 through PostgREST as `authenticated`.
```sql
BEGIN;
SET LOCAL role = 'authenticated';
SET LOCAL request.jwt.claims = '{"sub": "<user-uuid>", "role": "authenticated"}';
-- run your queries here and verify expected results
ROLLBACK;
```

**Client-Side Mutations (Supabase only):**
Search for direct `.insert()`, `.update()`, `.delete()` calls from frontend code on sensitive tables. These should be RPC functions instead.

**Edge Function Auth:**
For any Edge Function deployed with `--no-verify-jwt`, verify it has application-level auth checking.

**Service Role Key:**
Search for `service_role` or `createClient.*service` in frontend/client code -- should never appear there.

**Auth method:**
Verify `supabase.auth.getUser()` is used for server-side auth checks, NOT just `supabase.auth.getSession()`. Sessions can be spoofed client-side; `getUser()` validates the JWT against the auth server.

### 6.2 Firebase Checks (if FIREBASE flag set)

**Security Rules Audit (CRITICAL):**
Read `firestore.rules` and `storage.rules`. Flag:
- `allow read: if true` or `allow write: if true` -- full public access
- `allow read, write: if request.auth != null` -- any logged-in user can read/write anything (no ownership check)
- Missing rules file entirely (defaults to locked in production, but sometimes deployed with test rules)
- Wildcard collection rules that are too broad

**Admin SDK in Client Code:**
Search for Firebase Admin SDK usage in client-side files:
```
firebase-admin
admin\.firestore
admin\.auth
credential.*cert
```
The Admin SDK bypasses all security rules and should ONLY run server-side.

**Firestore Data Validation:**
Check: are Firestore writes validated in security rules with `request.resource.data` checks? Without rule-level validation, clients can write arbitrary fields.

**Firebase Config Exposure:**
Firebase config (`apiKey`, `projectId`, etc.) is designed to be public, but check that no service account JSON or admin credentials are bundled.

### 6.3 Convex Checks (if CONVEX flag set)

**Auth in Functions:**
For every `query` and `mutation` in `convex/` directory, check that `ctx.auth.getUserIdentity()` is called and its result is checked before accessing or modifying data.

**Public vs Internal Functions:**
Check that functions meant to be internal use `internalQuery` / `internalMutation` / `internalAction`, not `query` / `mutation` (which are callable from the client).

**Input Validation:**
Check that Convex `args` validators are used on all functions (e.g., `args: { id: v.id("tasks") }`) -- without validators, any data shape can be passed.

### 6.4 Clerk Checks (if CLERK flag set)

**Middleware Coverage:**
Check that `clerkMiddleware()` is applied in `middleware.ts` and covers all routes that need protection. Look for public route patterns that might be too broad:
```
publicRoutes.*\/api       # API routes accidentally marked public
publicRoutes.*\(\.\*\)    # Wildcard public routes
```

**Server-Side Verification:**
Check that API routes use `auth()` from `@clerk/nextjs/server` (not client-side hooks) to verify the user.

**Webhook Verification:**
If Clerk webhooks are used (for user sync), verify `svix` signature checking is implemented.

### 6.5 Auth.js / NextAuth Checks (if AUTHJS flag set)

**Secret Configuration:**
```
NEXTAUTH_SECRET          # Must be set in production
AUTH_SECRET              # Auth.js v5 equivalent
```
Check that the secret is not hardcoded and is set via environment variables.

**Callback Security:**
Check `callbacks` in auth config:
- `redirect` callback: does it validate URLs?
- `session` callback: does it expose sensitive user data?
- `jwt` callback: are custom claims validated?

**Provider Configuration:**
For OAuth providers, check that `clientId` and `clientSecret` are from env vars, not hardcoded.

**CSRF Protection:**
Auth.js has built-in CSRF for its own routes, but check that custom API routes also have protection.

### 6.6 Stripe / Payment Checks (if STRIPE flag set)

**Webhook Signature Verification (CRITICAL):**
Search for Stripe webhook handlers. Verify:
- `stripe.webhooks.constructEvent()` is called with the **raw request body** (not parsed JSON)
- The webhook signing secret (`whsec_`) is from environment variables
- Missing `stripe-signature` header results in rejection

**Price Tampering:**
Verify that prices/amounts come from your server/database, not from client requests:
```
req\.body\.price         # Client-supplied price -- CRITICAL
req\.body\.amount        # Client-supplied amount -- CRITICAL
```
Checkout Sessions and PaymentIntents must be created with server-side pricing.

**API Key Exposure:**
- `sk_live_` should NEVER appear in frontend code (only `pk_live_` or `pk_test_`)
- Check that Stripe secret key is only used in server-side code

**Idempotency:**
Check that webhook handlers are idempotent (processing the same event twice doesn't cause duplicate actions like double-charging or double-provisioning).

### 6.7 Next.js Checks (if NEXTJS flag set)

- **Server Actions:** do they validate auth at the top of each action? AI often generates Server Actions without auth checks.
- **API routes (`app/api/`):** do they all check authentication?
- **Middleware (`middleware.ts`):** does it cover ALL route types (pages AND API routes)? Real finding: middleware only protected pages, not `/api/*` routes.
- **`next.config.*`:** security headers configured? `poweredByHeader: false`?
- **Server vs Client components:** is sensitive logic (auth checks, database queries) in Server Components, not Client Components?

### 6.8 SvelteKit Checks (if SVELTEKIT flag set)

- **`hooks.server.ts`:** is auth validation in the `handle` hook?
- **`+page.server.ts` / `+server.ts`:** do `load` functions and API endpoints check auth?
- **`+page.ts` vs `+page.server.ts`:** is sensitive data loading in `+page.server.ts` (server-only), not `+page.ts` (runs on client)?
- **Form Actions:** do they validate auth before processing?

### 6.9 Nuxt Checks (if NUXT flag set)

- **Server routes (`server/api/`):** do they validate auth?
- **Middleware:** is auth middleware applied to protected routes?
- **`useRuntimeConfig()`:** are secrets in `runtimeConfig` (server-only), not `runtimeConfig.public`?

### 6.10 Chrome Extension Checks (if CHROME_EXT flag set)

- No hardcoded credentials in extension source
- CSP in extension manifest
- `postMessage` origin validation in content scripts
- Prefer `chrome.identity` over extracting tokens from page localStorage
- Minimum required permissions in `manifest.json`

### 6.11 AI/LLM Integration Checks (if OPENAI, ANTHROPIC, or AI SDK detected)

**API Key Proxying:**
LLM API keys must NEVER be in client-side code. Check that all AI calls go through a server-side proxy (API route, Server Action, or Edge Function).

**Prompt Injection Protection:**
Verify that user input is separated from system instructions:
- Vercel AI SDK: user content in `messages` with `role: "user"`, not concatenated into system prompt
- OpenAI: `messages` array with proper role separation
- Anthropic: `system` parameter separate from `messages`

**Cost Protection:**
- Input length limits before LLM calls
- Rate limiting on generation endpoints
- Max tokens configured on API calls
- No unbounded streaming without user limits

**Output Safety:**
- AI-generated content sanitized before rendering as HTML
- AI responses not used in `eval()`, SQL queries, or system commands
- System prompt not leaked via prompt injection (check for "ignore previous instructions" handling)

---

## Phase 7: API Contract & Type Safety [FULL ONLY]

### 7.1 Schema vs Interface Comparison

For projects with TypeScript interfaces and a database:
- Compare TypeScript interface field names against actual database column names
- The database is the source of truth, NOT the TypeScript interface
- Common finding: `is_favorited` in TS vs `is_favorite` in DB
- Supabase returns `snake_case`; Prisma returns `camelCase` by default; Drizzle follows your schema

### 7.2 Unsafe Type Assertions

Search for:
```
as any                   # Bypasses all type safety
as Type                  # May mask runtime mismatches (check if validated)
!                        # Non-null assertions (may hide null bugs)
@ts-ignore               # Suppressed type errors
@ts-expect-error         # Suppressed type errors
```

### 7.3 Missing Runtime Validation

Check: are API responses validated with Zod/Yup/Joi before use? Without validation, field name mismatches silently return `undefined` instead of throwing errors.

Positive signal: Zod schemas co-located with API routes and form handlers.

### 7.4 Field Name Mismatches

Search for snake_case vs camelCase confusion in API response handling. Check that frontend property access matches what the backend actually returns (especially JSONB nested structures from RPC functions).

### 7.5 Environment Variable Validation

Check: are required environment variables validated at startup (e.g., with `zod` or `t3-env`)? Missing env vars at runtime cause cryptic errors.

---

## Phase 8: Production Readiness [FULL ONLY]

### 8.1 Dev Bypasses in Production

Search for:
```
TODO.*remove
HACK
FIXME.*security
dev.*mode
test.*mode
if.*development
if.*process\.env\.NODE_ENV.*!==.*production
```

Verify no authentication bypasses are gated on a dev flag that could be flipped.

### 8.2 Debug Logging with Sensitive Data

Search for `console.log` in server-side code. Check if any log:
- Request/response bodies
- User data, tokens, passwords
- AI prompts, system instructions, and responses
- Error stacks (should be `console.error` only)
- Database query results

### 8.3 Test Functions in Production

Search for test/debug functions or endpoints that shouldn't exist in production:
```
test_                    # Test functions in database
debug                    # Debug endpoints
/test                    # Test routes
seed                     # Seed data functions
/__               # Internal debug routes (/__inspect, etc.)
```

### 8.4 Source Maps in Production

Check if source maps are exposed in production builds:
```
sourceMappingURL
devtool.*source-map      # Webpack config
productionSourceMap       # Vue/Nuxt config
```
Next.js: check `next.config.*` for `productionBrowserSourceMaps: true`.

### 8.5 Missing Error Handling

Check for unhandled promise rejections, missing try/catch around external API calls, and missing error boundaries in React / error pages in SvelteKit/Nuxt.

### 8.6 Environment Parity

Check for security-relevant settings that differ between dev and production:
- CORS configured for `localhost` only (will break or be insecure in production)
- HTTP-only cookies not set (because `localhost` doesn't use HTTPS)
- Debug mode enabled in framework config

---

## Output Format

Structure your report as follows:

```markdown
# Security Audit Report

**Scan Mode:** quick | standard | full
**Detected Stack:** [list detected technologies]
**Date:** [current date]

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | X |
| HIGH | Y |
| MEDIUM | Z |
| LOW | W |

**Overall Risk Level:** CRITICAL / HIGH / MEDIUM / LOW

## CRITICAL Findings

### [VULN-001] Title
- **File:** `path/to/file:line`
- **Description:** What's wrong
- **Exploit Scenario:** How an attacker exploits this (1-2 sentences)
- **Impact:** What damage results
- **Confidence:** HIGH / MEDIUM / LOW
- **Recommendation:** How to fix, with code example if applicable

## HIGH Findings
...

## MEDIUM Findings
...

## LOW Findings
...

## Positive Observations
- [List security measures already done well]
- [Acknowledge good practices to avoid alarm fatigue]

## Priority Action Items

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 1 | [Most critical fix] | Low/Med/High | [What it prevents] |
| 2 | ... | ... | ... |
```

**Rules for findings:**
- Every finding must include a specific file path and line number
- CRITICAL/HIGH findings must include an exploit scenario
- Include confidence level (HIGH = confirmed pattern, MEDIUM = likely issue, LOW = possible concern)
- Don't flag patterns that are clearly safe in context (e.g., `console.log("Server started")` is fine)
- Include positive observations -- acknowledge security done right
- For AI-generated codebases, note if a finding matches a known vibe coding anti-pattern

---

## Fix Pattern Library

When recommending fixes, use these proven patterns:

### Webhook Signature Verification (Stripe)
```typescript
// In your webhook route handler:
const sig = request.headers.get('stripe-signature');
if (!sig) return new Response('Missing signature', { status: 401 });
let event;
try {
  event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET!);
} catch (err) {
  return new Response('Invalid signature', { status: 401 });
}
// Process event...
```

### Generic Webhook Signature Verification
```typescript
if (!signature) {
  return new Response(JSON.stringify({ error: 'Missing signature' }), { status: 401 });
}
const isValid = await verifyWebhookSignature(rawBody, signature);
if (!isValid) {
  return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 401 });
}
```

### DOMPurify for dangerouslySetInnerHTML / {@html}
```tsx
import DOMPurify from 'dompurify';

// React
dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(content, { ALLOWED_TAGS: ['br', 'b', 'i', 'em', 'strong'], ALLOWED_ATTR: [] }),
}}

// Svelte
{@html DOMPurify.sanitize(content)}

// Or better for SVGs: render as data URI
<img src={`data:image/svg+xml;base64,${btoa(svgContent)}`} alt="..." />
```

### SSRF Protection
```typescript
function isUrlSafeToFetch(url: string): boolean {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) return false;
  const ip = parsed.hostname;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return false;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return false;
  if (ip === '169.254.169.254' || ip === 'metadata.google.internal') return false;
  if (ip === 'localhost' || ip === '0.0.0.0') return false;
  return true;
}
```

### PostgREST Filter Injection Prevention
```typescript
function sanitizeSearchInput(input: string): string {
  return input.replace(/[.,()\\]/g, '');
}
// Apply before every .or() / .ilike() interpolation
```

### Static Error Responses (Never Leak Internals)
```typescript
// Next.js
function errorResponse(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}
// Usage: return errorResponse("Failed to create resource", 500);
// NEVER: return NextResponse.json({ error: error.message }, { status: 500 });

// SvelteKit
throw error(500, { message: "Failed to create resource" });
// NEVER: throw error(500, { message: err.message });

// Express
res.status(500).json({ error: "Internal server error" });
// NEVER: res.status(500).json({ error: err.message, stack: err.stack });
```

### SECURITY DEFINER Function Template (Supabase)
```sql
CREATE OR REPLACE FUNCTION public.my_function(p_param TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  -- 1. Validate caller role
  IF NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'student') THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;
  -- 2. Validate inputs
  IF length(p_param) > 500 THEN
    RAISE EXCEPTION 'Input too long';
  END IF;
  -- 3. Business logic here
END;
$$;
REVOKE EXECUTE ON FUNCTION public.my_function FROM public;
GRANT EXECUTE ON FUNCTION public.my_function TO authenticated;
```

### SECURITY DEFINER Cycle-Breaker (RLS Recursion Fix)
Use this lighter pattern to break RLS circular dependencies. The function bypasses RLS internally, returning safe results that other policies can reference without creating cycles.
```sql
-- Example: break a cycle where profiles → class_students → classes → class_students
CREATE OR REPLACE FUNCTION public.get_user_class_ids()
RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$ SELECT class_id FROM class_students WHERE student_id = auth.uid() $$;

REVOKE EXECUTE ON FUNCTION public.get_user_class_ids() FROM public;
GRANT EXECUTE ON FUNCTION public.get_user_class_ids() TO authenticated;

-- Then replace the recursive policy subquery:
-- BEFORE (causes recursion): USING (id IN (SELECT class_id FROM class_students WHERE ...))
-- AFTER (breaks the cycle):  USING (id IN (SELECT get_user_class_ids()))
```

### RLS Policy Testing (as authenticated role)
```sql
-- Always test RLS as the runtime role, never as superuser
BEGIN;
SET LOCAL role = 'authenticated';
SET LOCAL request.jwt.claims = '{"sub": "<user-uuid>", "role": "authenticated"}';

-- Test your queries here -- they should behave identically to PostgREST/your app
SELECT * FROM your_table;

ROLLBACK;
```

### Firebase Security Rules Template
```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Default: deny all
    match /{document=**} {
      allow read, write: if false;
    }
    // Users can only read/write their own data
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    // Validate writes
    match /posts/{postId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null
        && request.resource.data.userId == request.auth.uid
        && request.resource.data.title is string
        && request.resource.data.title.size() <= 200;
      allow update, delete: if request.auth != null
        && resource.data.userId == request.auth.uid;
    }
  }
}
```

### Auth Check Patterns (by provider)

```typescript
// Clerk (Next.js App Router)
import { auth } from '@clerk/nextjs/server';
export async function POST(req: Request) {
  const { userId } = await auth();
  if (!userId) return new Response('Unauthorized', { status: 401 });
  // ...
}

// Auth.js v5 (Next.js)
import { auth } from '@/auth';
export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  // ...
}

// Supabase (use getUser, NOT getSession)
const { data: { user }, error } = await supabase.auth.getUser();
if (error || !user) return new Response('Unauthorized', { status: 401 });

// Firebase Admin (server-side)
const idToken = req.headers.authorization?.split('Bearer ')[1];
if (!idToken) return res.status(401).json({ error: 'Unauthorized' });
const decoded = await admin.auth().verifyIdToken(idToken);
```

### Rate Limiting
```typescript
const rateLimiter = new Map<string, { count: number; resetAt: number }>();
function checkRateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = rateLimiter.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimiter.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}
```

### Redirect URL Validation
```typescript
function safeRedirect(url: string | null, fallback: string = '/'): string {
  if (!url || !url.startsWith('/') || url.startsWith('//')) return fallback;
  return url;
}
```

### PostMessage Origin Validation (Exact Match)
```typescript
const ALLOWED_ORIGINS = ['https://www.example.com', 'https://example.com'];
window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.includes(event.origin)) return; // exact match, NOT .includes()
  // handle message
});
```

### Stripe Price Tampering Prevention
```typescript
// WRONG -- price from client:
const session = await stripe.checkout.sessions.create({
  line_items: [{ price_data: { unit_amount: req.body.price } }], // attacker controls price!
});

// CORRECT -- price from your database:
const product = await db.product.findUnique({ where: { id: req.body.productId } });
const session = await stripe.checkout.sessions.create({
  line_items: [{ price: product.stripePriceId }], // price from your server
});
```

### AI Prompt Injection Protection
```typescript
// WRONG -- user input in system prompt:
const response = await openai.chat.completions.create({
  messages: [{ role: "system", content: `Help with: ${userInput}` }],
});

// CORRECT -- user input in user message:
const response = await openai.chat.completions.create({
  messages: [
    { role: "system", content: "You are a helpful assistant." },
    { role: "user", content: userInput },
  ],
});
```

---

Now begin the security audit. Start with tech stack detection, then proceed through the phases appropriate for the selected scan depth. Be thorough but avoid false positives -- every finding should be actionable.
