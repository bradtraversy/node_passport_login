'use strict';
const assert = require('node:assert/strict');
const { spawn, fork, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const shared = path.join(__dirname, 'privacy-lib');
const sources = [path.join(shared, 'gdpr-router.cjs'), ...fs.readdirSync(path.join(shared, 'gdpr')).filter(x => x.endsWith('.rego')).map(x => path.join(shared, 'gdpr', x))];
const hashes = () => sources.map(file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'));
const before = hashes(), checks = [];
async function check(name, action) { await action(); checks.push({ name, passed: true }); console.log('PASS ' + name); }
async function freePort() {
  const reservation = net.createServer().listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const port = reservation.address().port; await new Promise(resolve => reservation.close(resolve)); return port;
}
function client(base) {
  const cookies = new Map();
  return async function request(route, { method = 'GET', body, token, timeoutMs = 15000 } = {}) {
    let url = base + route;
    for (let count = 0; count < 10; count++) {
      const headers = { Cookie: [...cookies].map(([k,v]) => k + '=' + v).join('; ') };
      if (body !== undefined) headers['Content-Type'] = typeof body === 'string' ? 'application/x-www-form-urlencoded' : 'application/json';
      if (token) headers['X-CSRF-Token'] = token;
      const response = await fetch(url, { method, headers, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body), redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(';')[0], i = pair.indexOf('='); cookies.set(pair.slice(0,i), pair.slice(i+1));
      }
      if ([301,302,303].includes(response.status)) {
        await response.text(); url = new URL(response.headers.get('location'), url).href; method='GET'; body=undefined; token=undefined; continue;
      }
      const text=await response.text(); let data; try { data=JSON.parse(text); } catch { data=text; }
      return {status:response.status, data, text, url};
    }
    throw new Error('Too many redirects');
  };
}
async function main() {
  const opaPort=await freePort(), port=await freePort(), base='http://localhost:'+port;
  const aliceEmail='alice-'+Date.now()+'@example.org', bobEmail='bob-'+Date.now()+'@example.org';
  const opa=spawn(process.env.OPA_BINARY || 'opa',['run','--server','--addr','127.0.0.1:'+opaPort,path.join(shared,'gdpr')],{stdio:'ignore',windowsHide:true});
  const backend=fork(path.join(root,'scripts/start-local.js'),[],{cwd:root,env:{...process.env,PORT:String(port),OPA_QUERY_URL:'http://127.0.0.1:'+opaPort+'/v1/query',GDPR_ADMIN_EMAILS:aliceEmail},stdio:['ignore','pipe','pipe','ipc'],windowsHide:true});
  let output=''; backend.stdout.on('data',chunk=>output+=chunk); backend.stderr.on('data',chunk=>output+=chunk);
  const alice=client(base), bob=client(base);
  async function csrf(c) { const r=await c('/gdpr'); return r.text.match(/name="_gdpr_csrf"\s+value="([^"]+)"/)?.[1]; }
  async function api(c,operation,body={},method='POST',includeToken=true,override) {
    return c('/gdpr/'+operation,{method,body,token:override??(includeToken?await csrf(c):undefined)});
  }
  const form=(c,route,body)=>c(route,{method:'POST',body:new URLSearchParams(body).toString()});
  try {
    let ready=false;
    const startupDeadline = Date.now() + 90000;
    while(Date.now() < startupDeadline) {
      if(backend.exitCode!==null) throw new Error(output);
      try {ready=(await alice('/users/register', { timeoutMs: 1000 })).status===200;if(ready)break;}catch{}
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.ok(ready,'Backend startup failed: '+output);
    await check('Unauthenticated GDPR request denied',async()=>assert.equal((await api(alice,'consent')).status,401));
    await form(alice,'/users/register',{name:'Alice Private Profile',email:aliceEmail,password:'Integration123',password2:'Integration123'});
    await form(alice,'/users/login',{email:aliceEmail,password:'Integration123'});
    await check('Original registration/login works',async()=>assert.ok((await alice('/dashboard')).text.includes('Alice Private Profile')));
    await alice('/users/logout');
    await form(alice,'/users/login',{email:aliceEmail,password:'Integration123'});
    await check('Original logout/password login works',async()=>assert.ok((await alice('/dashboard')).url.endsWith('/dashboard')));
    await check('Privacy page renders',async()=>assert.ok((await alice('/gdpr')).text.includes('Privacy checks')));
    await check('Missing CSRF token rejected',async()=>assert.equal((await api(alice,'consent',{},'POST',false)).status,403));
    await check('Missing consent rejects processing',async()=>assert.equal((await api(alice,'consent')).data,false));
    await check('Store consent in MongoDB',async()=>assert.deepEqual((await api(alice,'consent',{value:'yes',withdrawn:false},'PATCH')).data,{value:'yes',withdrawn:false}));
    for(const operation of ['consent','lawful']) await check(operation+' accepts stored consent',async()=>assert.equal((await api(alice,operation)).data,true));
    await check('Information report',async()=>assert.equal((await api(alice,'information')).data.consent_valid,true));
    let subject;
    await check('Access scoped to real user fields',async()=>{const r=await api(alice,'access');assert.equal(r.status,200);const value=JSON.parse(r.data.download.content);subject=value.user_id;assert.deepEqual(value.data_collected_from_user.map(x=>x.field).sort(),['email','name']);});
    await check('Rectification returns plan',async()=>{const r=await api(alice,'rectification',{updates:{name:'Updated Alice'}});assert.ok(r.data.request.validated);assert.ok(r.data.db_update_plan.some(x=>x.user_id===subject&&x.field==='name'));});
    await check('Retention exception rejects erasure',async()=>assert.equal((await api(alice,'erasure',{fields:['email']})).data.decision,'reject'));
    await check('Restriction returns plan',async()=>assert.equal((await api(alice,'restriction')).data.decision,'accept'));
    await check('Portability exports real values in JSON/CSV',async()=>{const r=await api(alice,'portability');assert.equal(r.data.decision,'accept');assert.equal(r.data.actions.downloads.length,2);assert.ok(JSON.stringify(r.data).includes(aliceEmail));assert.ok(JSON.stringify(r.data).includes('Alice Private Profile'));assert.ok(!JSON.stringify(r.data).includes('"password"'));});
    await check('Marketing objection returns stop plan',async()=>assert.equal((await api(alice,'objection',{reason:'marketing'})).data.decision,'accept'));
    await check('Complaint returns forwarding plan only',async()=>assert.equal((await api(alice,'complaint',{authority_id:'cy-0000',description:'Integration test only'})).data.decision,'accept'));
    await check('Explicitly configured admin assesses breach',async()=>assert.equal((await api(alice,'breach',{incident_id:'test-incident'})).data.decision,'notify_users'));
    await form(bob,'/users/register',{name:'Bob Private Profile',email:bobEmail,password:'Integration456',password2:'Integration456'});
    await form(bob,'/users/login',{email:bobEmail,password:'Integration456'});
    await check('Independent second user has no consent',async()=>assert.equal((await api(bob,'consent')).data,false));
    await check('Nonadmin cannot assess breach',async()=>assert.equal((await api(bob,'breach',{incident_id:'x'})).status,403));
    await api(bob,'consent',{value:'yes',withdrawn:false},'PATCH');
    await check('Bob export excludes Alice data',async()=>{const r=await api(bob,'portability');assert.ok(JSON.stringify(r.data).includes('Bob Private Profile'));assert.ok(!JSON.stringify(r.data).includes(aliceEmail));});
    await check('Alice export excludes Bob data',async()=>assert.ok(!JSON.stringify((await api(alice,'portability')).data).includes(bobEmail)));
    await check('Client cannot select another user',async()=>assert.equal((await api(bob,'access',{user_id:subject})).status,400));
    await check('Cross-session CSRF token rejected',async()=>assert.equal((await api(bob,'consent',{},'POST',true,await csrf(alice))).status,403));
    await check('Invalid CSRF token rejected',async()=>assert.equal((await api(alice,'consent',{},'POST',true,'invalid')).status,403));
    await check('Invalid consent update rejected',async()=>assert.equal((await api(alice,'consent',{value:'yes',withdrawn:'false'},'PATCH')).status,400));
    await check('Unknown operation rejected',async()=>assert.equal((await api(alice,'unknown')).status,400));
    await check('Withdraw consent',async()=>assert.equal((await api(alice,'consent',{value:'yes',withdrawn:true},'PATCH')).status,200));
    for(const operation of ['consent','lawful','portability']) await check(operation+' denies after withdrawal',async()=>{const r=await api(alice,operation);assert.equal(operation==='portability'?r.data.decision:r.data,operation==='portability'?'reject':false);});
    await check('Access remains available',async()=>assert.equal((await api(alice,'access')).data.request.validated,true));
    await check('Eligible erasure returns delete plan',async()=>assert.equal((await api(alice,'erasure',{fields:['name'],reason:'withdrawn_consent'})).data.decision,'accept'));
    await check('Decision-only plans did not modify account',async()=>assert.ok((await alice('/dashboard')).text.includes('Alice Private Profile')));
    await check('OPA failure returns 502',async()=>{const exited=once(opa,'exit');opa.kill();await exited;assert.equal((await api(alice,'consent')).status,502);});
    await check('Router and policies unchanged',async()=>assert.deepEqual(hashes(),before));
    const result={repository:'bradtraversy/node_passport_login',commit:execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8',windowsHide:true}).trim(),timestamp:new Date().toISOString(),passed:checks.length,checks,policies:['consent','lawful','information','access','rectification','erasure','restriction','portability','objection','complaint','breach'],limitations:['Decision plans only; no database changes or messages executed','Access returns metadata only','Synthetic policy metadata','Name and email mapped; password excluded','Breach assessment uses explicit test email allowlist; no upstream admin role']};
    require('./test-support.cjs').recordResult(result);
    console.log('Integration result: '+checks.length+'/'+checks.length+' passed');
  } finally {
    if(backend.exitCode===null&&backend.signalCode===null) {
      const exited=once(backend,'exit');backend.send('stop');const timer=setTimeout(()=>backend.kill(),15000);await exited;clearTimeout(timer);
    }
    if(opa.exitCode===null&&opa.signalCode===null)opa.kill();
  }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
