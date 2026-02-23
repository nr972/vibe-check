# Changelog

## [1.1.0] - 2025-02-23

### Added

- **PostgreSQL RLS recursion/cycle detection** -- Detects circular dependencies between RLS policies that cause infinite evaluation and 500 errors. Traces the policy dependency graph (A -> B -> C -> A cycles) and flags potential recursion sources with a concrete detection query.
- **`POSTGRES_RLS` auto-detection flag** -- RLS-specific checks now run for any PostgreSQL project using Row-Level Security, not just Supabase. Triggered by `CREATE POLICY` or `ENABLE ROW LEVEL SECURITY` in SQL/migration files, covering direct PostgreSQL, Neon, and ORM-backed projects.
- **RLS policy testing guidance** -- `SET LOCAL role = 'authenticated'` pattern for verifying policies as the actual runtime role instead of as superuser (which bypasses RLS entirely).
- **SECURITY DEFINER cycle-breaker fix pattern** -- `LANGUAGE sql STABLE SECURITY DEFINER` template for lightweight helper functions that break RLS recursion by bypassing RLS internally.
- **Detection query for tables missing RLS** -- `pg_tables` + `pg_class.relrowsecurity` query added to Phase 6.1.
- **Warning about tightening permissive policies** -- Documents that replacing `USING(true)` with a restrictive policy can unmask latent circular dependencies, since `USING(true)` acts as a circuit breaker.

### Changed

- Phase 6.1 broadened from "Supabase Checks" to "Supabase / PostgreSQL RLS Checks", scoping RLS-specific checks to trigger on either `SUPABASE` or `POSTGRES_RLS` flag while keeping Supabase-only checks (client-side mutations, Edge Function auth, service role key, `getUser()` vs `getSession()`) gated on `SUPABASE`.

## [1.0.0] - 2025-02-22

Initial release. 8-phase security audit skill covering 40+ technologies, built from 77+ real vulnerability findings across 6 production applications.
