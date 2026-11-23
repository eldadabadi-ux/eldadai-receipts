import { useState, useEffect, createContext, useContext } from 'react'
import { supabase } from '../lib/supabase'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(undefined) // undefined = loading
  const [session, setSession] = useState(null)

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session)
      setUser(session?.user ?? null)
    })
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session)
      setUser(session?.user ?? null)
    })
    return () => subscription.unsubscribe()
  }, [])

  /**
   * Tell the audit trail a session began (ASVS V16.3.1).
   *
   * Called from the explicit sign-in paths, deliberately NOT from
   * onAuthStateChange: that listener also fires on token refresh and on page
   * load with an existing session, which would turn one login into dozens of
   * entries and make the trail unreadable where it matters most.
   *
   * Best-effort and never awaited by the caller's critical path — a logging
   * failure must not be able to stop someone signing in.
   */
  async function recordSession(method) {
    try {
      const { data: { session: fresh } } = await supabase.auth.getSession()
      if (!fresh?.access_token) return
      await fetch('/api/account/session-event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fresh.access_token}` },
        body: JSON.stringify({ event: 'signed_in', method }),
      })
    } catch { /* the sign-in succeeded; the record is secondary */ }
  }

  async function signIn(email, password) {
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) throw error
    recordSession('password')
  }

  /**
   * supabase-js defaults signOut() to scope 'global', so this already ends the
   * user's sessions on every device, not just this one. Left as it is — for a
   * system holding financial records the safer default is the right one — but
   * stated here because the behaviour is surprising and undocumented upstream.
   */
  async function signOut() {
    await supabase.auth.signOut()
  }

  /**
   * End every OTHER session and stay signed in here (ASVS V7.5.2).
   *
   * The lever a person actually needs after losing a phone: today their only
   * option is a full sign-out, which also locks them out of the device they
   * are holding at the moment they are trying to secure the account.
   *
   * Listing those sessions is NOT offered, because this project's GoTrue has
   * no endpoint for it (`/admin/users/<id>/sessions` → 404). Showing a made-up
   * list would be worse than showing none.
   */
  async function signOutOthers() {
    const { error } = await supabase.auth.signOut({ scope: 'others' })
    if (error) throw error
    try {
      const { data: { session: fresh } } = await supabase.auth.getSession()
      if (fresh?.access_token) {
        await fetch('/api/account/session-event', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fresh.access_token}` },
          body: JSON.stringify({ event: 'signed_out_others' }),
        })
      }
    } catch { /* the revocation happened; the record is secondary */ }
  }

  // Change the password of the currently signed-in user.
  async function updatePassword(newPassword) {
    const { error } = await supabase.auth.updateUser({ password: newPassword })
    if (error) throw error
  }

  // Send a "forgot password" reset email. The link returns the user to
  // /reset-password where ResetPasswordPage establishes the session and lets
  // them set a new password.
  async function requestPasswordReset(email) {
    const redirectTo = `${window.location.origin}/reset-password`
    const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo })
    if (error) throw error
  }

  // GDPR / right-to-erasure. The anon client cannot delete an auth user, so a
  // server Function (service-role) purges all of the user's data + storage and
  // then deletes the auth user. Afterwards we sign out locally.
  async function deleteAccount() {
    const { data: { session: fresh } } = await supabase.auth.getSession()
    const token = fresh?.access_token
    if (!token) throw new Error('לא מחובר')
    const res = await fetch('/api/account/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    })
    let body = {}
    try { body = await res.json() } catch {}
    if (!res.ok) throw new Error(body?.message || body?.error || 'מחיקת החשבון נכשלה')
    await supabase.auth.signOut()
  }

  return (
    <AuthContext.Provider value={{
      user, session,
      signIn, signOut, signOutOthers, recordSession,
      updatePassword, requestPasswordReset, deleteAccount,
      loading: user === undefined,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
