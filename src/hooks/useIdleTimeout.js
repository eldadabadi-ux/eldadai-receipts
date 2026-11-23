/**
 * useIdleTimeout — sign out after a long stretch of no interaction.
 *
 * ASVS V7.3.1. Until now there was no inactivity limit at all, and the
 * behaviour in place was simply the Supabase default — a default, not a
 * decision, which for a system holding a business's financial records is the
 * part worth fixing.
 *
 * WHAT THIS IS, HONESTLY: a screen lock. It protects the common real case —
 * the tablet left on the counter, the browser open on a shared back-office
 * machine — by ending the session when nobody has touched it for hours.
 *
 * WHAT IT IS NOT: a defence against a stolen token. Anyone holding the access
 * token can use it until the token itself expires, and no amount of
 * client-side timing changes that. The server-side half of this requirement is
 * the token lifetime configured in Supabase (Auth → Sessions), and the two are
 * complementary rather than alternatives. Saying so matters: a timeout that
 * looks like a security boundary but is only a UX one is worse than none,
 * because it stops people asking for the real control.
 *
 * FOUR HOURS, and the reasoning is the business, not the standard: receipts
 * are scanned in bursts through a working day, so a shorter limit would eject
 * a café owner mid-shift and train them to resent the product. Four hours of
 * *zero* interaction means the person walked away.
 *
 * Shared across tabs through localStorage, so three open tabs are one session
 * rather than three independent clocks — otherwise a forgotten background tab
 * keeps the whole account alive.
 */
import { useEffect, useRef } from 'react'

/** Idle limit. One constant, one place to change it. */
export const IDLE_LIMIT_MS = 4 * 60 * 60 * 1000      // 4 hours

const KEY = 'moses_last_activity'
const CHECK_EVERY_MS = 60 * 1000                      // a minute's granularity is plenty
const WRITE_THROTTLE_MS = 30 * 1000                   // don't touch storage on every mousemove

const now = () => Date.now()

function readLast() {
  try {
    const v = Number(localStorage.getItem(KEY))
    return Number.isFinite(v) && v > 0 ? v : null
  } catch { return null }                             // private mode / storage blocked
}

function writeLast(t) {
  try { localStorage.setItem(KEY, String(t)) } catch { /* ignore */ }
}

/** Clear the marker — call on sign-out so the next session starts fresh. */
export function clearIdleMarker() {
  try { localStorage.removeItem(KEY) } catch { /* ignore */ }
}

/**
 * @param {boolean}  active  only run while someone is signed in
 * @param {function} onIdle  what to do when the limit is passed (sign out)
 * @param {number}   [limit] override, for tests
 */
export function useIdleTimeout(active, onIdle, limit = IDLE_LIMIT_MS) {
  const onIdleRef = useRef(onIdle)
  onIdleRef.current = onIdle

  useEffect(() => {
    if (!active) return

    // A session that starts with a stale marker from last week must not be
    // killed on its first tick — treat mount as activity.
    let lastWrite = 0
    const touch = () => {
      const t = now()
      if (t - lastWrite < WRITE_THROTTLE_MS) return
      lastWrite = t
      writeLast(t)
    }
    writeLast(now())

    // `visibilitychange` matters most: returning to a tab after a long absence
    // is exactly when the check should fire, and a background tab's timers are
    // throttled hard by the browser.
    const EVENTS = ['pointerdown', 'keydown', 'scroll', 'touchstart', 'visibilitychange']
    for (const e of EVENTS) {
      window.addEventListener(e, touch, { passive: true, capture: true })
    }

    const check = () => {
      const last = readLast()
      if (last === null) return                       // storage unavailable → do not sign anyone out
      if (now() - last > limit) {
        clearIdleMarker()
        onIdleRef.current?.()
      }
    }

    const id = setInterval(check, CHECK_EVERY_MS)
    // And immediately on return to the tab, rather than up to a minute later.
    const onVisible = () => { if (document.visibilityState === 'visible') check() }
    document.addEventListener('visibilitychange', onVisible)

    return () => {
      clearInterval(id)
      document.removeEventListener('visibilitychange', onVisible)
      for (const e of EVENTS) window.removeEventListener(e, touch, { capture: true })
    }
  }, [active, limit])
}
