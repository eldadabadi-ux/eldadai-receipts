/**
 * /api/admin/flags — owner-only management of per-customer module flags
 * (client request #10, SaaS packaging). Feature-flag rows are service-role-write
 * only (RLS blocks end users), so flipping a module for a customer runs here.
 *
 *   GET  → { orgs:[{id,name,plan,subscription_status}], overrides:[{key,org_id,enabled}],
 *           globals:[{key,enabled}], modules:[key] }
 *   POST { orgId, key, enabled }  enabled=null clears the override (back to default)
 *        → { ok }
 */
import { wrapAuthErrors } from '../_lib/auth.js'
import { guardOwner } from '../_lib/guards.js'
import { writeAudit } from '../_lib/audit.js'
import { errorResponse } from '../_lib/response.js'
import { MODULE_FLAGS, FLAG_KEYS } from '../_lib/flags.js'

const cors = { 'Content-Type': 'application/json' }


export const onRequestGet = wrapAuthErrors(async (context) => {
  const g = await guardOwner(context)
  if (g.res) return g.res
  const { url, headers } = g
  const [orgs, flags] = await Promise.all([
    fetch(`${url}/rest/v1/organizations?select=id,name,business_name,plan,subscription_status&order=name`, { headers }).then(r => r.ok ? r.json() : []),
    fetch(`${url}/rest/v1/feature_flags?select=key,org_id,enabled,note`, { headers }).then(r => r.ok ? r.json() : []),
  ])
  return Response.json({
    orgs,
    overrides: (flags || []).filter(f => f.org_id),
    globals: (flags || []).filter(f => !f.org_id),
    modules: MODULE_FLAGS,
  }, { headers: cors })
})

export const onRequestPost = wrapAuthErrors(async (context) => {
  const g = await guardOwner(context)
  if (g.res) return g.res
  const { caller, url, headers } = g

  let body
  try { body = await context.request.json() } catch { return Response.json({ error: 'bad_json' }, { status: 400, headers: cors }) }
  const orgId = (body?.orgId || '').trim()
  const key = (body?.key || '').trim()
  const enabled = body?.enabled
  if (!orgId) return Response.json({ error: 'missing_org' }, { status: 400, headers: cors })
  if (!FLAG_KEYS.includes(key)) return Response.json({ error: 'unknown_flag' }, { status: 400, headers: cors })

  const scope = `key=eq.${encodeURIComponent(key)}&org_id=eq.${encodeURIComponent(orgId)}`

  if (enabled === null || enabled === undefined) {
    // Clear the override → the tenant falls back to global/default.
    const del = await fetch(`${url}/rest/v1/feature_flags?${scope}`, { method: 'DELETE', headers })
    if (!del.ok) {
      return errorResponse('ביטול ההגדרה נכשל', 400, {
        code: 'write_failed', err: (await del.text()).slice(0, 500), headers: cors,
      })
    }
    await writeAudit(context.env, { orgId, userId: caller.user_id, action: 'flag_cleared', target: key })
    return Response.json({ ok: true, cleared: true }, { headers: cors })
  }

  const on = !!enabled
  const existing = await fetch(`${url}/rest/v1/feature_flags?${scope}&select=id`, { headers }).then(r => r.ok ? r.json() : [])
  let res
  if (existing?.[0]?.id) {
    res = await fetch(`${url}/rest/v1/feature_flags?id=eq.${existing[0].id}`, {
      method: 'PATCH', headers, body: JSON.stringify({ enabled: on, updated_at: new Date().toISOString() }) })
  } else {
    res = await fetch(`${url}/rest/v1/feature_flags`, {
      method: 'POST', headers, body: JSON.stringify({ key, org_id: orgId, enabled: on, note: 'admin console' }) })
  }
  if (!res.ok) {
    return errorResponse('שמירת ההגדרה נכשלה', 400, {
      code: 'write_failed', err: (await res.text()).slice(0, 500), headers: cors,
    })
  }
  await writeAudit(context.env, { orgId, userId: caller.user_id, action: 'flag_set', target: key, meta: { enabled: on } })
  return Response.json({ ok: true, enabled: on }, { headers: cors })
})
