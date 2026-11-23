/**
 * audit-chain-diagnose — verify the audit hash chain from outside Postgres.
 *
 *   npm run audit:chain
 *
 * Reimplements the trigger's formula in JS, byte-for-byte: Postgres' jsonb
 * text form (keys ordered by length then bytewise, ": " and ", " separators)
 * and timestamptz::text in UTC. Calibrated against known-good rows - row 1
 * reproduces exactly - so a mismatch it reports is a real mismatch.
 *
 * Why it exists: verify_audit_chain() stops at the FIRST bad row and says
 * nothing about why. That is enough to raise an alarm and not enough to act
 * on. This prints EVERY failing row and correlates the failures, which is how
 * finding N14 was resolved:
 *
 *     org_id set   ->  72 rows, 72 verify,  0 fail
 *     org_id NULL  ->  38 rows,  0 verify, 38 fail
 *
 * — a total correlation that pointed straight at
 * `org_id REFERENCES organizations(id) ON DELETE SET NULL`. Deleting an
 * organization rewrote rows of an append-only table and left their hashes
 * behind. Fixed by supabase_audit_chain_fix.sql.
 *
 * Needs .env.test (SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY). Read-only.
 */
const {createClient}=require('@supabase/supabase-js')
const crypto=require('crypto')
const a=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false}})
const sha=s=>crypto.createHash('sha256').update(s,'utf8').digest('hex')
function jsonbText(v){
  if(v===null||v===undefined) return null
  const enc=o=>{
    if(o===null) return 'null'
    if(Array.isArray(o)) return '['+o.map(enc).join(', ')+']'
    if(typeof o==='object'){
      const ks=Object.keys(o).sort((x,y)=> x.length!==y.length ? x.length-y.length : (x<y?-1:x>y?1:0))
      return '{'+ks.map(k=>JSON.stringify(k)+': '+enc(o[k])).join(', ')+'}'
    }
    return JSON.stringify(o)
  }
  return enc(v)
}
function tsText(iso,offsetMin=0){
  const d=new Date(iso), s=new Date(d.getTime()+offsetMin*60000)
  const frac=(iso.match(/\.(\d+)/)||[,''])[1].replace(/0+$/,'')
  const p=n=>String(n).padStart(2,'0')
  const off=offsetMin===0?'+00':(offsetMin>0?'+':'-')+p(Math.abs(offsetMin)/60)
  return s.getUTCFullYear()+'-'+p(s.getUTCMonth()+1)+'-'+p(s.getUTCDate())+' '+p(s.getUTCHours())+':'+p(s.getUTCMinutes())+':'+p(s.getUTCSeconds())+(frac?'.'+frac:'')+off
}
const hashOf=(r,off=0)=>sha((r.prev_hash||'')+(r.action||'')+(r.target||'')+(jsonbText(r.meta)||'')+(r.user_id||'')+(r.org_id||'')+tsText(r.created_at,off))
;(async()=>{
  const {data}=await a.from('audit_log').select('*').order('id',{ascending:true})
  let prev='', linkage=[], content=[]
  for(const r of data){
    if((r.prev_hash||'')!==prev) linkage.push(r)
    if(r.row_hash!==hashOf(r)) content.push(r)
    prev=r.row_hash
  }
  console.log('total rows        :',data.length)
  console.log('linkage breaks    :',linkage.length, linkage.map(r=>r.id).join(','))
  console.log('content mismatches:',content.length, content.map(r=>r.id).join(','))
  console.log('')
  for(const r of content.slice(0,12)){
    console.log('--- id',r.id,'| action',r.action,'| at',r.created_at)
    let tzHit=null
    for(const off of [0,60,120,180,-240,-300,330]) if(hashOf(r,off)===r.row_hash) tzHit=off
    console.log('    timezone reproduces stored hash?', tzHit===null?'NO':('YES at offset '+tzHit))
    console.log('    meta:', JSON.stringify(r.meta))
    console.log('    target:', JSON.stringify(r.target), '| org:', r.org_id, '| user:', r.user_id)
  }
})()
