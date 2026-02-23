# /vibe-check -- Security Audit for Vibe-Coded Apps

A Claude Code slash command that scans any codebase for security vulnerabilities and suggests fixes. Built from 77+ real vulnerability findings across 6 production applications, expanded with coverage for the full vibe coding ecosystem.

## Install

### Option A: Direct file install (simplest)

Copy the command file to your global Claude Code commands directory:

```bash
# One-liner install
curl -o ~/.claude/commands/vibe-check.md \
  https://raw.githubusercontent.com/nr972/vibe-check/main/commands/vibe-check.md
```

Or clone and copy:

```bash
git clone https://github.com/nr972/vibe-check.git
cp vibe-check/commands/vibe-check.md ~/.claude/commands/
```

After installing, use it as `/vibe-check` in any project.

### Option B: Test without installing

```bash
claude --plugin-dir ./vibe-check
```

## Usage

```
/vibe-check              # Standard scan (Phases 1-6)
/vibe-check quick        # Secrets + critical vulns only (Phases 1-2)
/vibe-check full         # Comprehensive audit (all 8 phases)
```

## What it checks

### Phases

| Phase | Focus | Modes |
|-------|-------|-------|
| 1 | **Secret detection** -- API keys (OpenAI, Stripe, Supabase, Firebase, Clerk, AWS), tokens, passwords, database connection strings, client-side auth secrets | all |
| 2 | **Critical vulnerabilities** -- auth bypass, SQL/command injection, database security gaps (RLS, Security Rules, RLS recursion detection), webhook signature bypass, privilege escalation, client-side auth logic | all |
| 3 | **OWASP Top 10** -- XSS, IDOR, SSRF, CORS misconfiguration, sensitive data exposure, NoSQL injection, prompt injection | standard, full |
| 4 | **Input validation** -- length limits, file uploads, rate limiting, weak randomness, redirect validation, postMessage origin checks | standard, full |
| 5 | **Dependencies** -- `npm audit`, unused packages, hallucinated packages ("slopsquatting"), deprecated libraries, security headers, SRI | standard, full |
| 6 | **Stack-specific checks** -- 11 conditional modules based on detected tech stack (see below) | standard, full |
| 7 | **API contract & type safety** -- schema vs interface mismatches, unsafe type assertions, missing runtime validation | full |
| 8 | **Production readiness** -- dev bypasses, debug logging, test functions, source maps, environment parity | full |

### Auto-detected stacks (40+ technologies)

The skill auto-detects your tech stack from `package.json`, config files, and directory structure, then runs targeted checks.

**Frontend:** Next.js, React, SvelteKit, Nuxt, Astro, Remix, Angular, Express, Fastify, Django, Flask, Rails

**BaaS / Database:** Supabase, Firebase, Convex, Prisma, Drizzle, MongoDB/Mongoose, PlanetScale, Neon, PostgreSQL RLS (auto-detected from migration files)

**Auth:** Clerk, Auth.js/NextAuth, Better Auth, Supabase Auth, Firebase Auth, Lucia (flags as deprecated)

**Payments:** Stripe (webhook verification, price tampering, key exposure), Lemon Squeezy, Paddle

**AI/LLM:** OpenAI, Anthropic, Vercel AI SDK, Replicate, Google Gemini -- checks for prompt injection, API key proxying, cost protection

**Deployment:** Vercel, Netlify, Cloudflare Workers/Pages, Railway, Fly.io, Docker, GitHub Actions

**Other:** Chrome Extensions, Resend, UploadThing, Zod

### Stack-specific check modules (Phase 6)

| Module | Activates when | Key checks |
|--------|---------------|------------|
| Supabase / PostgreSQL RLS | `@supabase/supabase-js`, `supabase/` dir, or SQL files with `CREATE POLICY` | RLS gaps, `USING(true)`, RLS recursion/cycle detection, SECURITY DEFINER audit, RLS policy testing, `getUser()` vs `getSession()`, service role key exposure, client-side mutations |
| Firebase | `firebase` in deps or `firebase.json` | Security Rules audit (`allow write: if true`), Admin SDK in client code, Firestore write validation |
| Convex | `convex` in deps or `convex/` dir | Auth in queries/mutations, public vs internal functions, arg validators |
| Clerk | `@clerk` in deps | Middleware coverage, server-side verification, webhook signature checking |
| Auth.js | `next-auth` or `@auth/core` in deps | Secret configuration, callback security, CSRF protection |
| Stripe | `stripe` in deps | Webhook signature verification, price tampering, API key exposure, idempotency |
| Next.js | `next` in deps or config | Server Action auth, API route auth, middleware coverage, security headers |
| SvelteKit | `@sveltejs/kit` in deps or config | `hooks.server.ts` auth, server vs client data loading, form action auth |
| Nuxt | `nuxt` in deps or config | Server route auth, runtime config secrets, middleware |
| Chrome Extension | `manifest.json` with `manifest_version` | Hardcoded credentials, CSP, postMessage validation, permissions |
| AI/LLM | OpenAI, Anthropic, or AI SDK in deps | API key proxying, prompt injection, cost protection, output safety |

## Output format

The skill produces a structured markdown report:

- **Summary table** with finding counts by severity (CRITICAL / HIGH / MEDIUM / LOW)
- **Findings** with file path, line number, description, exploit scenario, confidence level, and fix recommendation
- **Positive observations** to acknowledge good security practices and avoid alarm fatigue
- **Priority action items** table with effort estimates

Each finding includes a proven fix pattern with code examples.

## How it was built

This skill was distilled from 19 security documents across 6 production applications:

- **77+ real vulnerability findings** catalogued by severity
- **Search patterns proven to find real bugs** -- every grep pattern in the skill caught an actual vulnerability
- **Fix templates from real remediations** -- webhook verification, DOMPurify, SSRF protection, rate limiting, SECURITY DEFINER templates (including RLS cycle-breaker pattern), RLS policy testing, Firebase Security Rules, auth check patterns for Clerk/Auth.js/Supabase/Firebase
- **Vibe coding anti-patterns** from Wiz Research, Vidoc Security, and Kaspersky -- client-side auth, exposed API keys, slopsquatting, missing input validation

## Contributing

Found a vulnerability pattern that should be included? Open an issue or PR. The goal is to cover the most common security mistakes across the tools developers actually use.

## License

MIT -- Copyright (c) 2026 Noam Raz / Pleasant Secret Labs
