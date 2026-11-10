/* ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari. */
/* ProxyCircuit v0.2.0-beta TLS, users, bulk domain management - no third-party frontend dependencies */
'use strict';
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const esc = (x) => String(x ?? '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]));
let csrf = '', currentView = 'dashboard', modalKind = '', editID = null;
let data = {hosts: [],streams: [],certificates: [],audit:[],summary:null};
let toastTimer = null;
const titles = {dashboard:'Übersicht',hosts:'Proxy-Domains',streams:'TCP / UDP Ports',certificates:'SSL-Zertifikate',monitoring:'Monitoring & Logs',plugins:'Plugins',backups:'Backup & Export'};

async function api(path, options={}) {
  const method = options.method || 'GET';
  const headers = {...(options.headers||{})};
  if(options.body && !headers['Content-Type']) headers['Content-Type']='application/json';
  if(!['GET','HEAD'].includes(method.toUpperCase())) headers['X-CSRF-Token'] = csrf;
  let r;
  try { r = await fetch('/api'+path,{...options,method,headers,credentials:'same-origin'}); }
  catch(e){throw new Error('Keine Verbindung zum Backend: '+e.message);}
  let result;
  try {result=await r.json();}catch{throw new Error('Serverantwort ist nicht lesbar (HTTP '+r.status+')');}
  if(!r.ok){
    if(r.status===401){logoutVisual();}
    const detail = result.detail;
    const msg = Array.isArray(detail) ? detail.map(d=>`${(d.loc||[]).slice(1).join('.')}: ${d.msg}`).join('; ') : String(detail || 'Anfrage fehlgeschlagen');
    throw new Error(msg);
  }
  return result;
}
function toast(message,error=false){const el=$('#toast');el.textContent=message;el.className='toast'+(error?' error':'');clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.add('hidden'),5200);}
function logoutVisual(){csrf='';window.PC_ROLE='';$('#shell').classList.add('hidden');$('#loginScreen').classList.remove('hidden');}
function loginVisual(user,role='viewer'){window.PC_ROLE=role;$('#usersNav')?.classList.toggle('hidden',role!=='admin');$('#rolePill').textContent=role==='admin'?'Administrator':role==='editor'?'Bearbeiter':'Leser';$('#loginScreen').classList.add('hidden');$('#shell').classList.remove('hidden');$('#avatar').textContent=(user||'A').slice(0,1).toUpperCase();}
async function login(e) {
  e.preventDefault();
  // Capture the form synchronously: event.currentTarget becomes null after dispatch.
  const formElement = e.currentTarget;
  const fields = new FormData(formElement);
  const error = $('#loginError');
  error.textContent = '';

  // Secure session cookies are intentionally not transmitted over plain HTTP.
  // Never submit administrator credentials over an unencrypted proxy hostname.
  if (window.location.protocol !== 'https:') {
    error.textContent = 'Anmeldung ueber HTTP gesperrt. Bitte ProxyCircuit ueber die geschuetzte HTTPS-Adresse im LAN oder VPN oeffnen.';
    return;
  }

  try {
    const result = await api('/login', {
      method: 'POST',
      body: JSON.stringify({username: fields.get('username'), password: fields.get('password')})
    });
    csrf = result.csrf;
    const passwordField = formElement.querySelector('input[name="password"]');
    if (passwordField) passwordField.value = '';
    loginVisual(result.username,result.role);
  } catch (err) {
    error.textContent = err.message;
    return;
  }

  // Login succeeded: a dashboard fetch error must not be reported as a login error.
  try {
    await refreshAll();
  } catch (err) {
    toast('Angemeldet, aber Dashboard-Daten konnten nicht geladen werden: ' + err.message, true);
  }
}
async function logout(){try{await api('/logout',{method:'POST'});}catch{}logoutVisual();}
function nav(view){currentView=view;$$('.view').forEach(el=>el.classList.toggle('hidden',el.id!=='view-'+view));$$('.nav-item[data-view]').forEach(el=>el.classList.toggle('active',el.dataset.view===view));$('#crumb').textContent=titles[view];if(view==='monitoring') refreshMonitoring();if(view==='plugins')refreshPlugins();if(view==='backups')refreshDeploy();}
function statusHTML(enabled){return `<span class="status ${enabled?'':'off'}">${enabled?'● Eingeschaltet':'● Ausgeschaltet'}</span>`;}
function fmtDate(s){if(!s)return '–';let dt=new Date(s);return Number.isNaN(dt.getTime())?'–':dt.toLocaleDateString('de-DE');}
function percent(v){return Math.min(100,Math.max(0,Number(v)||0));}
function prettyBytes(bytes){let b=Number(bytes)||0;return b>1e9?(b/1e9).toFixed(2)+' GB':b>1e6?(b/1e6).toFixed(1)+' MB':Math.round(b/1000)+' KB';}
async function refreshAll(){
  const responses=await Promise.allSettled([api('/hosts'),api('/streams'),api('/certificates'),api('/audit'),api('/summary')]);
  ['hosts','streams','certificates','audit','summary'].forEach((k,i)=>{if(responses[i].status==='fulfilled')data[k]=responses[i].value;});
  renderDashboard();renderHosts();renderStreams();renderCerts();await refreshDeploy();
}
function renderDashboard(){
 const s=data.summary||{};
 const specs=[['Proxy-Domains',s.hosts_active??'–',`${s.hosts_total??0} insgesamt`,'◎'],['TCP / UDP Regeln',s.streams_active??'–',`${s.streams_total??0} insgesamt`,'⇄'],['SSL-Warnungen',s.certs_expiring_30d??'–','Ablauf innerhalb 30 Tagen','♢'],['Verbindungen',s.connections??'–','Aktive Nginx-Verbindungen','⌁']];
 $('#metricCards').innerHTML=specs.map(([name,num,desc,ico])=>`<div class="metric"><div class="metric-head"><span>${esc(name)}</span><span class="metric-icon">${ico}</span></div><div class="metric-num">${esc(num)}</div><div class="metric-sub">${esc(desc)}</div></div>`).join('');
 const rows=[['CPU',s.cpu_percent,'%'],['RAM',s.ram_percent,`% · ${s.ram_used_mb??'–'} / ${s.ram_total_mb??'–'} MB`]];
 $('#resourceStats').innerHTML=rows.map(([name,v,post])=>`<div class="resource-row"><div class="resource-top"><b>${name}</b><span>${esc(v??'–')}${esc(post)}</span></div><div class="track"><progress value="${percent(v)}" max="100" aria-label="${esc(name)}-Auslastung"></progress></div></div>`).join('')+
 `<p class="net-usage-note">Netzwerk seit Systemstart: <b>${prettyBytes(s.bytes_recv)} empfangen</b> / <b>${prettyBytes(s.bytes_sent)} gesendet</b></p>`;
 $('#auditList').innerHTML=data.audit.length?data.audit.slice(0,5).map(a=>`<div class="audit-entry"><span class="audit-symbol">✓</span><div><strong>${esc(a.action)} · ${esc(a.description)}</strong><small>${esc(a.username)} · ${fmtDate(a.created_at)}</small></div></div>`).join(''):'<div class="empty">Noch keine Änderungen registriert.</div>';
}
function renderHosts(){
 $('#hostsRows').innerHTML=data.hosts.length?data.hosts.map(h=>`<tr><td><strong>${esc(h.domain)}</strong><small>Proxy-ID: ${esc(h.id)}</small></td><td><span class="mono">${esc(h.upstream_scheme)}://${esc(h.upstream_host)}:${Number(h.upstream_port)}</span></td><td>${h.certificate_id?'<span class="status">🔒 HTTPS</span>':'<span class="status pending">HTTP</span>'}<small>WebSocket: ${h.websocket?'Ja':'Nein'} · HTTPS-Zwang: ${h.force_https?'Ja':'Nein'}</small></td><td>${statusHTML(h.enabled)}</td><td><button class="mini-button" data-action="diagnoseHost" data-id="${esc(h.id)}">Vollanalyse</button><button class="mini-button" data-action="editHost" data-id="${esc(h.id)}">Bearbeiten</button><button class="mini-button red" data-action="deleteHost" data-id="${esc(h.id)}">Löschen</button></td></tr>`).join(''):'<tr><td colspan="5" class="empty">Noch keine Domains vorhanden. Über „Domain hinzufügen“ beginnen.</td></tr>';
}
function renderStreams(){
 $('#streamRows').innerHTML=data.streams.length?data.streams.map(s=>`<tr><td><strong>${esc(s.label)}</strong><small>Timeout: ${Number(s.timeout_seconds)}s</small></td><td><span class="status ${s.protocol==='udp'?'pending':''}">${esc(s.protocol.toUpperCase())}</span></td><td><strong class="mono">${Number(s.listen_port)}</strong></td><td class="mono">${esc(s.target_host)}:${Number(s.target_port)}</td><td>${statusHTML(s.enabled)}</td><td><button class="mini-button" data-action="editStream" data-id="${esc(s.id)}">Bearbeiten</button><button class="mini-button red" data-action="deleteStream" data-id="${esc(s.id)}">Löschen</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">Noch keine Portregeln vorhanden.</td></tr>';
}
function renderCerts(){
 $('#certRows').innerHTML=data.certificates.length?data.certificates.map(c=>`<tr><td><strong>${esc(c.domain)}</strong><small>${esc(c.label)}</small></td><td>${c.kind==='acme'?'Let\'s Encrypt':'PEM-Import'}</td><td>${fmtDate(c.expires_at)}</td><td><span class="status ${c.status==='ready'?'':c.status==='pending'?'pending':'error'}">${esc(c.status)}</span>${c.error?`<small title="${esc(c.error)}">${esc(c.error.slice(0,105))}</small>`:''}</td><td><button class="mini-button red" data-action="deleteCert" data-id="${esc(c.id)}">Löschen</button></td></tr>`).join(''):'<tr><td colspan="5" class="empty">Keine Zertifikate vorhanden. Ein Zertifikat importieren oder über HTTP-01 anfordern.</td></tr>';
}
async function refreshDeploy(){
 try{
 const d=await api('/deploy');const s=d.status||{};
 const message=d.state==='pending'?'Die Änderung wartet auf die Aktivierung. Letzte Rückmeldung: '+(s.message||'noch keine'):(s.message||'Noch keine Aktivierung erfolgt.');
 $('#deployState').textContent=`Status: ${d.state} · ${message}`;
 const hostState=$('#hostDeployState'); if(hostState)hostState.textContent=`Letzter Nginx-Deploy: ${d.state}. ${message}`;
 const el=$('#deployBanner');el.textContent=d.state==='error'?'⚠ '+message:d.state==='pending'?'⏳ Konfigurationsänderung wartet auf Aktivierung.':'✓ '+message;el.className='status-banner'+(d.state==='error'?' error':'');
 }catch(e){$('#deployState').textContent=e.message;}
}
function field(label,name,value='',extra='',span=''){
 return `<label class="${span}">${label}<input name="${name}" value="${esc(value)}" ${extra}></label>`;
}
function checkbox(label,name,checked){return `<label class="checkbox-line span2"><input type="checkbox" name="${name}" ${checked?'checked':''}> ${label}</label>`;}
function selectField(label,name,items,selected,span=''){
 return `<label class="${span}">${label}<select name="${name}">${items.map(([val,title])=>`<option value="${esc(val)}" ${String(val)===String(selected)?'selected':''}>${esc(title)}</option>`).join('')}</select></label>`;
}
function openModal(kind,id=null){
 modalKind=kind;editID=id;$('#modalError').textContent='';$('#modalOverlay').classList.remove('hidden');let html='',title='',btn='Speichern';
 if(kind==='host'){
   const h=data.hosts.find(x=>x.id===id)||{};title=id?'Proxy-Domain bearbeiten':'Neue Proxy-Domain';
   const certs=[['','Kein Zertifikat (nur HTTP)'],...data.certificates.filter(x=>x.status==='ready').map(x=>[x.id,x.domain+' · '+x.kind])];
   html=`<div class="form-grid">${field('Domain / Subdomain','domain',h.domain||'','placeholder="app.example.de" required','span2')}
   ${selectField('Upstream-Protokoll','upstream_scheme',[['http','HTTP'],['https','HTTPS']],h.upstream_scheme||'http')}
   ${field('Ziel-IP / Hostname','upstream_host',h.upstream_host||'','placeholder="10.0.0.50" required')}
   ${field('TLS-Servername des HTTPS-Ziels (optional)','upstream_tls_name',h.upstream_tls_name||'','placeholder="proxycircuit.local"','span2')}
   ${field('Eigener Host-Header am Ziel (optional)','upstream_host_header',h.upstream_host_header||'','placeholder="z. B. keyhelp.internal"','span2')}
   ${field('Kategorie / Hauptgruppe (optional)','category',h.category||'','placeholder="z. B. AfghanHost"','span2')}
   ${field('Zielport','upstream_port',h.upstream_port||8080,'type="number" min="1" max="65535" required')}
   ${selectField('SSL-Zertifikat','certificate_id',certs,h.certificate_id||'')}
   ${checkbox('WebSocket-Unterstützung', 'websocket',h.websocket===undefined?true:!!h.websocket)}
   ${checkbox('HTTP automatisch nach HTTPS umleiten','force_https',!!h.force_https)}
   ${checkbox('Proxy aktiv','enabled',h.enabled===undefined?true:!!h.enabled)}</div>`;
 }else if(kind==='stream'){
   const s=data.streams.find(x=>x.id===id)||{};title=id?'Portregel bearbeiten':'Neue TCP / UDP Portregel';
   html=`<div class="form-grid">${field('Dienstname','label',s.label||'','placeholder="SSH / Datenbank / App" required','span2')}
   ${selectField('Protokoll','protocol',[['tcp','TCP'],['udp','UDP']],s.protocol||'tcp')}
   ${field('Externer Port am Proxy','listen_port',s.listen_port||2222,'type="number" min="1" max="65535" required')}
   ${field('Ziel-IP / Hostname','target_host',s.target_host||'','placeholder="10.0.0.50" required')}
   ${field('Zielport','target_port',s.target_port||22,'type="number" min="1" max="65535" required')}
   ${field('Timeout (Sekunden)','timeout_seconds',s.timeout_seconds||300,'type="number" min="1" max="3600" required','span2')}
   ${checkbox('Regel aktiv','enabled',s.enabled===undefined?true:!!s.enabled)}</div>`;
 }else if(kind==='acme'){
   title="Let's-Encrypt-Zertifikat";btn='Zertifikat anfordern';
   const opts=data.hosts.filter(h=>h.enabled&& !h.domain.startsWith('*.')).map(h=>[h.domain,h.domain]);
   html=`<div class="form-grid">${opts.length?selectField('Aktive Domain','domain',opts,opts[0][0],'span2'):'<p class="span2">Zuerst eine aktive Proxy-Domain anlegen.</p>'}
   ${field('Kontakt-E-Mail für ACME','email','','type="email" placeholder="admin@example.de" required','span2')}</div><div class="info-bar">HTTP-01 benötigt öffentliche Domainauflösung und Port 80 auf diesem LXC. Die Ausstellung läuft über den systemd-Arbeiter.</div>`;
 }else if(kind==='pem'){
   title='Eigenes PEM-Zertifikat importieren';btn='Zertifikat prüfen und importieren';
   html=`<div class="form-grid">${field('Bezeichnung','label','','placeholder="Mein Zertifikat" required','span2')}${field('Zertifikatsdomain','domain','','placeholder="app.example.de oder *.example.de" required','span2')}
   <label class="span2">Vollständige Zertifikatskette (PEM)<textarea name="fullchain_pem" required placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
   <label class="span2">Privater Schlüssel (PEM, unverschlüsselt)<textarea name="private_key_pem" required placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label></div>`;
 }
 $('#modalTitle').textContent=title;$('#modalFields').innerHTML=html;$('#saveModal').textContent=btn;$('#modalForm').querySelector('input,select,textarea')?.focus();
}
function closeModal(){$('#modalOverlay').classList.add('hidden');$('#modalForm').reset();modalKind='';editID=null;}
async function saveModal(event){
 event.preventDefault();const form=new FormData(event.currentTarget);let path='',method='POST',payload={};$('#modalError').textContent='';$('#saveModal').disabled=true;
 try{
  if(modalKind==='host'){
    payload={domain:form.get('domain'),upstream_scheme:form.get('upstream_scheme'),upstream_host:form.get('upstream_host'),upstream_port:Number(form.get('upstream_port')),upstream_tls_name:(form.get('upstream_tls_name')||'').trim()||null,
      websocket:form.has('websocket'),force_https:form.has('force_https'),certificate_id:form.get('certificate_id')||null,category:form.get('category')||'',upstream_host_header:(form.get('upstream_host_header')||'').trim()||null,enabled:form.has('enabled')};
    path='/hosts'+(editID?'/'+editID:'');method=editID?'PUT':'POST';
  }else if(modalKind==='stream'){
    payload={label:form.get('label'),protocol:form.get('protocol'),listen_port:Number(form.get('listen_port')),target_host:form.get('target_host'),
      target_port:Number(form.get('target_port')),timeout_seconds:Number(form.get('timeout_seconds')),enabled:form.has('enabled')};
    path='/streams'+(editID?'/'+editID:'');method=editID?'PUT':'POST';
  }else if(modalKind==='acme'){payload={domain:form.get('domain'),email:form.get('email')};path='/certificates/issue';}
  else if(modalKind==='pem'){payload={label:form.get('label'),domain:form.get('domain'),fullchain_pem:form.get('fullchain_pem'),private_key_pem:form.get('private_key_pem')};path='/certificates/import';}
  if(!path)throw new Error('Unbekannte Aktion');
  const result=await api(path,{method,body:JSON.stringify(payload)});closeModal();
  if(result.deployment?.state==='error')toast('Gespeichert, aber Nginx-Aktivierung konnte nicht angefordert werden: '+result.deployment.message,true);
  else toast('Änderung gespeichert. Nginx-Aktivierung wird geprüft.');
  await refreshAll();
 }catch(err){$('#modalError').textContent=err.message;}finally{$('#saveModal').disabled=false;}
}
async function actionClick(ev){
 const btn=ev.target.closest('[data-action]');if(!btn)return;const action=btn.dataset.action,id=btn.dataset.id;
 if(action==='diagnoseHost')return runDomainDiagnostics(id);
 if(action==='editHost')return openModal('host',id);
 if(action==='editStream')return openModal('stream',id);
 if(['deleteHost','deleteStream','deleteCert'].includes(action)){
  const type=action==='deleteHost'?'hosts':action==='deleteStream'?'streams':'certificates';
  if(!confirm('Diesen Eintrag wirklich entfernen? Die vorherige Nginx-Konfiguration bleibt bis zur erfolgreichen Aktivierung erhalten.'))return;
  try{await api('/'+type+'/'+id,{method:'DELETE'});toast('Eintrag entfernt; Nginx-Aktivierung läuft.');await refreshAll();}catch(err){toast(err.message,true);}
 }
}
async function runDomainDiagnostics(id){
 nav('monitoring');
 const output=$('#routeDiagnostic');
 output.textContent='Pruefe Domain-Routing, internes HTTPS, Upstream und DNS ...';
 try {
   const r=await api('/hosts/'+encodeURIComponent(id)+'/diagnostics');
   const nginx=r.nginx||{}, upstream=r.upstream||{}, dns=r.dns||{}, tls=r.local_https||{};
   const status=(x)=>x===true?'Ja':x===false?'Nein':'Unbekannt';
   const lines=[
      `Domain: ${r.domain}`,
      `Nginx-Regel: HTTP=${status(nginx.http)}, HTTPS=${status(nginx.https)}`,
      `Lokaler HTTPS-Test (127.0.0.1:443, SNI): ${tls.state}${tls.http_status?' | HTTP '+tls.http_status:''}${tls.error?' | '+tls.error:''}`,
      `Zielserver: ${upstream.state} | ${upstream.code||''} | ${upstream.message||''}${upstream.http_status?' | HTTP '+upstream.http_status:''}${upstream.error?' | '+upstream.error:''}`,
      `Aktives Nginx-Ziel: ${r.applied_nginx_upstream?.proxy_pass||'nicht auslesbar'}`,
      `Nginx TLS: Pruefung=${r.applied_nginx_upstream?.tls_verification||'unbekannt'}, SNI=${r.applied_nginx_upstream?.tls_name||'(Standard: Ziel-IP/Hostname)'}, CA=${r.applied_nginx_upstream?.trusted_ca_path||'unbekannt'}`,
      r.applied_nginx_upstream?.matches_database_upstream===false?'WARNUNG: Gespeicherte Regel und aktive Nginx-Regel weichen ab.':'',
      ...((r.recommendations||[]).map(s=>'KONFIGURATION: '+s)),
      ...((upstream.suggestions||[]).map(s=>'EMPFEHLUNG: '+s)),
      upstream.certificate?.sha256_fingerprint?'Zielzertifikat SHA256: '+upstream.certificate.sha256_fingerprint:'',
      upstream.certificate?.dns_names?.length?'Zertifikat DNS-Namen: '+upstream.certificate.dns_names.join(', '):'',
      upstream.certificate?.expires_at?'Zertifikat gueltig bis: '+upstream.certificate.expires_at:'',
      upstream.unverified_backend?.reachable?'BACKEND DIREKTAUFRUF (TLS nur zu Diagnosezwecken ungeprueft): HTTP '+upstream.unverified_backend.http_status+(upstream.unverified_backend.page_title?' | Seitentitel: '+upstream.unverified_backend.page_title:'')+(upstream.unverified_backend.redirect?' | Weiterleitung: '+upstream.unverified_backend.redirect:''):'',
      upstream.certificate?.details?'ZIEL-ZERTIFIKAT (nur Diagnose):\n'+upstream.certificate.details:'',
      upstream.redirect?`Zielserver-Weiterleitung: ${upstream.redirect}`:'',
      `DNS-A-Adressen: ${(dns.addresses||[]).join(', ')||'keine'}${dns.error?' | '+dns.error:''}`,
      'Oeffentlicher Zugriff: NICHT GEPRUEFT – NAT/Router und ggf. vorgeschalteten NPM gesondert kontrollieren.',
      '',
      'Windows PowerShell – ProxyCircuit direkt statt oeffentlicher Route:',
      `curl.exe -vI --resolve ${r.domain}:443:${/^\d+\.\d+\.\d+\.\d+$/.test(window.location.hostname)?window.location.hostname:"<PROXYCIRCUIT-IP>"} https://${r.domain}/`,
      '',
      'Windows PowerShell – oeffentlicher Weg:',
      `curl.exe -vI https://${r.domain}/`
   ];
   output.textContent=lines.filter(x=>x!==null).join('\n');
 } catch(err){output.textContent='Diagnose fehlgeschlagen: '+err.message;}
}
async function refreshMonitoring(){
 try{let result=await api('/healthchecks');$('#healthRows').innerHTML=result.length?result.map(x=>`<div class="health-chip"><strong>${esc(x.name)}</strong><span class="status ${x.status==='online'?'':['offline','tls_error','error','misconfigured'].includes(x.status)?'off':'pending'}">${esc(x.type)} · ${esc(x.status)}${x.code?" · HTTP "+esc(x.code):""}</span>${x.hint?`<small>${esc(x.hint)}</small>`:""}</div>`).join(''):'<p>Noch keine aktiven Dienste eingetragen.</p>';}catch(e){$('#healthRows').textContent=e.message;}
 await refreshLogs();
}
async function refreshLogs(){if(currentView!=='monitoring')return;try{let r=await api('/logs?kind='+encodeURIComponent($('#logType').value)+'&lines=100');$('#logOutput').textContent=r.error||r.lines.join('')||'Noch keine Logeinträge.';}catch(e){$('#logOutput').textContent=e.message;}}
async function refreshPlugins(){try{let p=await api('/plugins');$('#pluginRows').innerHTML=p.installed.length?p.installed.map(x=>`<div class="plugin"><strong>${esc(x.name)} <span class="status pending">v${esc(x.version)}</span></strong><small>${esc(x.description)}</small></div>`).join(''):'<p>Noch keine Plugin-Manifeste installiert.</p>';}catch(e){$('#pluginRows').textContent=e.message;}}
async function exportConfig(){try{let json=await api('/export');let blob=new Blob([JSON.stringify(json,null,2)],{type:'application/json'});let url=URL.createObjectURL(blob);let a=document.createElement('a');a.href=url;a.download='rpmgr-konfiguration-'+new Date().toISOString().slice(0,10)+'.json';document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);toast('JSON-Konfiguration exportiert (ohne geheime Schlüssel).');}catch(e){toast(e.message,true);}}
async function retryDeploy(){try{await api('/deploy',{method:'POST'});toast('Nginx-Konfigurationsprüfung angefordert.');setTimeout(refreshDeploy,1400);}catch(e){toast(e.message,true);}}
function bind(){
 $('#loginForm').addEventListener('submit',login);$('#logout').addEventListener('click',logout);
 $('#navigation').addEventListener('click',e=>{const btn=e.target.closest('[data-view]');if(btn)nav(btn.dataset.view);});
 $('#quickHost').addEventListener('click',()=>openModal('host'));$('#addHost').addEventListener('click',()=>openModal('host'));$('#addStream').addEventListener('click',()=>openModal('stream'));
 $('#issueCert').addEventListener('click',()=>openModal('acme'));$('#importCert').addEventListener('click',()=>openModal('pem'));
 $('#modalForm').addEventListener('submit',saveModal);$('#closeModal').addEventListener('click',closeModal);$('#cancelModal').addEventListener('click',closeModal);
 $('#modalOverlay').addEventListener('click',e=>{if(e.target.id==='modalOverlay')closeModal();});
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});
 $('#hostsRows').addEventListener('click',actionClick);$('#streamRows').addEventListener('click',actionClick);$('#certRows').addEventListener('click',actionClick);
 $('#refreshHealth').addEventListener('click',refreshMonitoring);$('#logType').addEventListener('change',refreshLogs);
 $('#exportConfig').addEventListener('click',exportConfig);$('#exportConfig2').addEventListener('click',exportConfig);
 $('#retryDeploy').addEventListener('click',retryDeploy);
}
async function boot(){
 bind();$('#serverTime').textContent=new Date().toLocaleDateString('de-DE',{weekday:'short',day:'numeric',month:'short',year:'numeric'});
 try{let u=await api('/me');csrf=u.csrf;loginVisual(u.username,u.role);await refreshAll();}catch{logoutVisual();}
 setInterval(async()=>{if(!csrf)return;try{data.summary=await api('/summary');if(currentView==='dashboard')renderDashboard();}catch{}},12000);
 setInterval(async()=>{if(!csrf)return;if(currentView==='monitoring')await refreshLogs();await refreshDeploy();},5000);
}
boot();
