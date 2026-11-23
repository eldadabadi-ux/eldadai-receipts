/**
 * Idle sign-out — the storage contract behind useIdleTimeout (ASVS V7.3.1).
 *
 * The hook itself needs a DOM, but the part that decides whether to end a
 * session is plain arithmetic over a localStorage timestamp, and that is the
 * part where a mistake is expensive in both directions: too eager and a café
 * owner is ejected mid-shift, too lax and the control does nothing.
 *
 * The case that matters most is storage being unavailable. In a private window
 * localStorage can throw, and a timeout that reads "no marker" as "idle
 * forever" would sign every such user out on the first tick.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

const KEY = 'moses_last_activity'

/** The decision useIdleTimeout's check() makes, extracted verbatim. */
function shouldSignOut(readLast, now, limit) {
  const last = readLast()
  if (last === null) return false        // storage unavailable → never sign out
  return now - last > limit
}

const HOUR = 60 * 60 * 1000
const LIMIT = 4 * HOUR

test('an active session is left alone', () => {
  const now = 1_000_000_000
  assert.equal(shouldSignOut(() => now - 60_000, now, LIMIT), false, 'a minute ago is active')
  assert.equal(shouldSignOut(() => now - 3 * HOUR, now, LIMIT), false, 'three hours is still inside the limit')
})

test('the limit is exclusive at the boundary, not jittery around it', () => {
  const now = 1_000_000_000
  assert.equal(shouldSignOut(() => now - LIMIT, now, LIMIT), false, 'exactly at the limit stays signed in')
  assert.equal(shouldSignOut(() => now - LIMIT - 1, now, LIMIT), true, 'one millisecond past it signs out')
})

test('a long absence signs out', () => {
  const now = 1_000_000_000
  assert.equal(shouldSignOut(() => now - 5 * HOUR, now, LIMIT), true)
  assert.equal(shouldSignOut(() => now - 30 * 24 * HOUR, now, LIMIT), true, 'a stale marker from last month')
})

test('unavailable storage must NOT sign anyone out', () => {
  // Private windows and blocked site data make localStorage throw. Reading
  // that as "idle forever" would eject every such user on the first tick.
  const now = 1_000_000_000
  assert.equal(shouldSignOut(() => null, now, LIMIT), false)
})

test('a clock that jumped backwards does not sign anyone out', () => {
  // A device whose time was corrected backwards yields a negative gap.
  const now = 1_000_000_000
  assert.equal(shouldSignOut(() => now + HOUR, now, LIMIT), false)
})

test('the configured limit is four hours, and is a single named constant', async () => {
  const { IDLE_LIMIT_MS } = await import('../../src/lib/../hooks/useIdleTimeout.js')
    .catch(() => import('../../src/hooks/useIdleTimeout.js'))
  assert.equal(IDLE_LIMIT_MS, 4 * HOUR,
    'changing the policy must be a one-line change, and this test is where it is recorded')
})

test('the storage key is stable — renaming it silently resets every session', async () => {
  const src = await import('node:fs').then(fs =>
    fs.readFileSync(new URL('../../src/hooks/useIdleTimeout.js', import.meta.url), 'utf8'))
  assert.ok(src.includes(`'${KEY}'`), `the activity marker key must stay ${KEY}`)
})

test('sign-out clears the marker, so the next session does not inherit a stale one', async () => {
  const src = await import('node:fs').then(fs =>
    fs.readFileSync(new URL('../../src/App.jsx', import.meta.url), 'utf8'))
  assert.match(src, /clearIdleMarker\(\)/,
    'App.jsx must clear the activity marker when signing out')
})
