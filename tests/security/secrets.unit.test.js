/**
 * Secret hygiene — the tracked tree and the client bundle
 * (ASVS V14 · ISO A.5.18, A.8.24, A.8.31)
 *
 * gitleaks is not installed on the build machine, and a scanner nobody runs is
 * not a control. These are the few assertions that actually matter for this
 * repo, written so they run everywhere `node --test` does:
 *
 *   - the service-role key, which bypasses every RLS policy in the product,
 *     must never reach a tracked file or the browser bundle;
 *   - .env must never become tracked;
 *   - no private key or provider token may be committed.
 *
 * The anon key is deliberately NOT treated as a secret: it is published in the
 * client bundle by design and is only useful together with RLS.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('../..', import.meta.url))

const git = (...args) => {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
  } catch { return null }
}

const tracked = (git('ls-files') || '').split('\n').map(s => s.trim()).filter(Boolean)

/** Decode a JWT payload without verifying — we only want the `role` claim. */
function jwtRole(token) {
  try {
    const p = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(Buffer.from(p + '='.repeat((4 - p.length % 4) % 4), 'base64').toString()).role
  } catch { return null }
}

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g

test('the git inventory loaded (otherwise these tests prove nothing)', () => {
  assert.ok(tracked.length > 20, `only ${tracked.length} tracked files — is this a git repo?`)
})

test('no .env file is tracked', () => {
  const leaked = tracked.filter(f => /(^|\/)\.env$/.test(f) || /(^|\/)\.env\.(local|production|test)$/.test(f))
  assert.deepEqual(leaked, [], 'an environment file is committed')
})

test('.gitignore still covers the environment files', () => {
  const gi = readFileSync(join(ROOT, '.gitignore'), 'utf8')
  for (const pattern of ['.env', '.env.test']) {
    assert.ok(gi.split('\n').some(l => l.trim() === pattern), `.gitignore no longer ignores ${pattern}`)
  }
})

test('no service-role JWT appears in any tracked file', () => {
  const offenders = []
  for (const f of tracked) {
    if (/^tests\/security\/secrets\.unit\.test\.js$/.test(f)) continue   // this file
    const full = join(ROOT, f)
    if (!existsSync(full)) continue
    let text
    try { text = readFileSync(full, 'utf8') } catch { continue }
    for (const m of text.match(JWT_RE) || []) {
      const role = jwtRole(m)
      // anon is public by design; service_role bypasses every RLS policy.
      if (role && role !== 'anon') offenders.push(`${f} (role=${role})`)
    }
  }
  assert.deepEqual(offenders, [], 'a non-anon Supabase key is committed — ROTATE IT, then remove it')
})

test('no provider API key or private key is committed', () => {
  const PATTERNS = [
    [/sk-ant-[A-Za-z0-9_-]{20,}/, 'Anthropic API key'],
    [/AIza[0-9A-Za-z_-]{33}/, 'Google API key'],
    [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, 'private key'],
    [/xox[baprs]-[A-Za-z0-9-]{10,}/, 'Slack token'],
    [/ghp_[A-Za-z0-9]{36}/, 'GitHub token'],
  ]
  const offenders = []
  for (const f of tracked) {
    if (/^tests\/security\/secrets\.unit\.test\.js$/.test(f)) continue
    const full = join(ROOT, f)
    if (!existsSync(full)) continue
    let text
    try { text = readFileSync(full, 'utf8') } catch { continue }
    for (const [re, label] of PATTERNS) if (re.test(text)) offenders.push(`${f}: ${label}`)
  }
  assert.deepEqual(offenders, [], 'a credential is committed — ROTATE IT, then remove it')
})

test('the service-role key is never referenced from client code', () => {
  const offenders = []
  const walk = (dir) => {
    for (const name of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, name.name)
      if (name.isDirectory()) walk(p)
      else if (/\.(js|jsx|ts|tsx)$/.test(name.name)) {
        const text = readFileSync(p, 'utf8')
        if (/SERVICE_ROLE/i.test(text)) offenders.push(p.slice(ROOT.length))
      }
    }
  }
  walk(join(ROOT, 'src'))
  assert.deepEqual(offenders, [], 'client code references the service-role key')
})

test('the built bundle carries no non-anon key', () => {
  const dist = join(ROOT, 'dist', 'assets')
  if (!existsSync(dist)) return   // not built in this environment — nothing to check
  const offenders = []
  for (const name of readdirSync(dist)) {
    if (!name.endsWith('.js')) continue
    const text = readFileSync(join(dist, name), 'utf8')
    for (const m of text.match(JWT_RE) || []) {
      const role = jwtRole(m)
      if (role && role !== 'anon') offenders.push(`${name} (role=${role})`)
    }
    if (/sk-ant-|AIza[0-9A-Za-z_-]{33}/.test(text)) offenders.push(`${name} (provider key)`)
  }
  assert.deepEqual(offenders, [], 'a server-side credential was bundled into the browser build')
})
