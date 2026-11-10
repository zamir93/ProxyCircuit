/* ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari. */
'use strict';

/* These extensions reuse the original login, CSRF-protected API client and forms. */
const chosenHosts = new Set();
const collapsedDomains = new Set();
let filteredHostList = [];
let userRows = [];
const pcCanWrite = () => ['admin','editor'].includes(window.PC_ROLE);
const pcIsAdmin = () => window.PC_ROLE === 'admin';

function rootDomain(domain){
  const parts=String(domain).toLowerCase().replace(/^\*\./,'').split('.');
  if(parts.length<=2)return parts.join('.');
  const commonMulti=new Set(['co.uk','org.uk','ac.uk','com.au','net.au','com.br','co.jp','com.tr','com.cn']);
  const suffix=parts.slice(-2).join('.');
  return parts.slice(-(commonMulti.has(suffix)?3:2)).join('.');
}
function groupFor(host){return (host.category||'').trim() || rootDomain(host.domain);}
function isMainHost(host){return host.domain === rootDomain(host.domain);}

const _oldRenderHosts = renderHosts;
renderHosts = function renderHostsGrouped(){
  const all = data.hosts||[];
  for(const id of chosenHosts){if(!all.some(h=>h.id===id))chosenHosts.delete(id);}
  const groups=[...new Set(all.map(groupFor))].sort((a,b)=>a.localeCompare(b,'de'));
  const groupSelect=$('#hostGroup');
  const oldValue=groupSelect?.value||'all';
  if(groupSelect){
    groupSelect.innerHTML='<option value="all">Alle Hauptdomains</option>'+groups.map(g=>`<option value="${esc(g)}">${esc(g)}</option>`).join('');
    groupSelect.value=groups.includes(oldValue)?oldValue:'all';
  }
  const query=($('#hostSearch')?.value||'').trim().toLowerCase();
  const status=$('#hostStatus')?.value||'all';
  const group=groupSelect?.value||'all';
  filteredHostList=all.filter(h=>{
    if(group!=='all'&&groupFor(h)!==group)return false;
    if(query&&!`${h.domain} ${h.upstream_scheme} ${h.upstream_host} ${h.upstream_port} ${groupFor(h)}`.toLowerCase().includes(query))return false;
    if(status==='on'&&!h.enabled || status==='off'&&h.enabled)return false;
    if(status==='tls'&&!h.certificate_id || status==='plain'&&h.certificate_id)return false;
    return true;
  });
  const grouped=!!$('#hostGroupMode')?.checked;
  const sorted=[...filteredHostList].sort((a,b)=>{
    const g=groupFor(a).localeCompare(groupFor(b),'de');
    if(grouped&&g)return g;
    if(isMainHost(a)!==isMainHost(b))return isMainHost(a)?-1:1;
    return a.domain.localeCompare(b.domain,'de');
  });
  let previous='';
  const parts=[];
  const canWrite=pcCanWrite();
  for(const h of sorted){
    const groupName=groupFor(h);
    if(grouped&&groupName!==previous){
      const total=all.filter(x=>groupFor(x)===groupName).length;
      parts.push(`<tr class="domain-group-header"><td colspan="6"><button type="button" data-feature="toggleGroup" data-group="${esc(groupName)}" aria-expanded="${!collapsedDomains.has(groupName)}"><span>${collapsedDomains.has(groupName)?'▸':'▾'}</span> <strong>◉ ${esc(groupName)}</strong> <small>${total} Domains</small></button></td></tr>`);
      previous=groupName;
    }
    if(grouped&&collapsedDomains.has(groupName))continue;
    const cert=data.certificates.find(c=>c.id===h.certificate_id);
    const canRenew=canWrite&&cert?.kind==='acme'&&cert?.status==='ready';
    parts.push(`<tr class="host-row"><td><input type="checkbox" data-host-id="${esc(h.id)}" aria-label="${esc(h.domain)} auswählen" ${chosenHosts.has(h.id)?'checked':''}></td>
      <td><div class="domain-cell"><strong>${esc(h.domain)}</strong>${isMainHost(h)?'<span class="domain-tag primary-domain">Hauptdomain</span>':'<span class="domain-tag">Subdomain</span>'}</div><small>${esc(groupName)} · ${esc(h.id)}</small></td>
      <td><span class="mono">${esc(h.upstream_scheme)}://${esc(h.upstream_host)}:${Number(h.upstream_port)}</span>${h.upstream_tls_name?`<small>SNI: ${esc(h.upstream_tls_name)}</small>`:''}</td>
      <td>${h.certificate_id?'<span class="status">🔒 HTTPS</span>':'<span class="status pending">HTTP</span>'}${cert?.expires_at?`<small>bis ${fmtDate(cert.expires_at)}</small>`:''}</td>
      <td>${statusHTML(h.enabled)}</td>
      <td class="row-actions"><button class="mini-button" data-action="diagnoseHost" data-id="${esc(h.id)}">Vollanalyse</button>${canWrite?`<button class="mini-button" data-action="editHost" data-id="${esc(h.id)}">Bearbeiten</button>${canRenew?`<button class="mini-button" data-feature="renewCert" data-id="${esc(cert.id)}">SSL erneuern</button>`:''}<button class="mini-button red" data-action="deleteHost" data-id="${esc(h.id)}">Löschen</button>`:''}</td></tr>`);
  }
  $('#hostsRows').innerHTML=parts.join('')||'<tr><td colspan="6" class="empty">Keine Domains für diesen Filter gefunden.</td></tr>';
  $('#selectionCount').textContent=chosenHosts.size+' ausgewählt';
  $('#domainCounter').textContent=filteredHostList.length+' von '+all.length+' Domains angezeigt · '+groups.length+' Hauptgruppen';
  const selectAll=$('#hostSelectAll');
  if(selectAll){
    selectAll.checked=filteredHostList.length>0&&filteredHostList.every(h=>chosenHosts.has(h.id));
    selectAll.indeterminate=filteredHostList.some(h=>chosenHosts.has(h.id))&&!selectAll.checked;
  }
  $('#bulkActions')?.classList.toggle('hidden',!canWrite);
  $('#addHost')?.classList.toggle('hidden',!canWrite);
  $('#quickHost')?.classList.toggle('hidden',!canWrite);
};

renderCerts = function renderCertsEnhanced(){
  const canWrite=pcCanWrite();
  $('#certRows').innerHTML=(data.certificates||[]).length?data.certificates.map(c=>{
    const inUse=data.hosts.filter(h=>h.certificate_id===c.id).length;
    return `<tr><td><strong>${esc(c.domain)}</strong><small>${esc(c.label)} · ${inUse} zugewiesen</small></td>
      <td>${c.kind==='acme'?"Let's Encrypt":'PEM-Import'}</td><td>${fmtDate(c.expires_at)}</td>
      <td><span class="status ${c.status==='ready'?'':c.status==='pending'?'pending':'error'}">${esc(c.status)}</span>${c.error?`<small title="${esc(c.error)}">${esc(c.error.slice(0,130))}</small>`:''}</td>
      <td>${canWrite?(c.kind==='acme'?`<button class="mini-button" data-feature="renewCert" data-id="${esc(c.id)}" ${c.status!=='ready'?'disabled':''}>↻ Erneuern</button>`:`<button class="mini-button" data-feature="replaceCert" data-id="${esc(c.id)}">PEM ersetzen</button>`)+`<button class="mini-button red" data-action="deleteCert" data-id="${esc(c.id)}">Löschen</button>`:''}</td></tr>`;
  }).join(''):'<tr><td colspan="5" class="empty">Keine Zertifikate vorhanden.</td></tr>';
  $('#importCert')?.classList.toggle('hidden',!canWrite);
  $('#issueCert')?.classList.toggle('hidden',!canWrite);
};

const _oldNav=nav;
nav=function(view){
  if(view==='users'&&!pcIsAdmin())return;
  _oldNav(view);
  if(view==='users')refreshUsers();
};

async function pcBulkAction(action){
  if(!pcCanWrite())return;
  const ids=[...chosenHosts];
  if(!ids.length){toast('Bitte mindestens eine Domain auswählen.',true);return;}
  const payload={ids,action,delete_certificates:false,category:''};
  if(action==='categorize'){
    const value=prompt('Neue Hauptgruppe / Kategorie (leer = automatisch nach Hauptdomain):','');
    if(value===null)return;
    payload.category=value;
  }
  if(action==='delete'){
    payload.delete_certificates=!!$('#bulkDeleteCerts')?.checked;
    const text=`${ids.length} Domains endgültig löschen?`+(payload.delete_certificates?' Nicht anderweitig verwendete Zertifikate werden ebenfalls entfernt.':' Zertifikate bleiben erhalten.')+' Vorher Root-Backup erstellen!';
    if(!confirm(text))return;
  }else if(action!=='categorize'&&!confirm(`${ids.length} Domains ${action==='enable'?'aktivieren':'deaktivieren'}?`))return;
  try{
    const result=await api('/hosts/bulk',{method:'POST',body:JSON.stringify(payload)});
    chosenHosts.clear();
    const detail=result.result||{};
    toast(`${detail.count||ids.length} Domains bearbeitet.${detail.certificates_kept_shared?` ${detail.certificates_kept_shared} gemeinsam verwendete Zertifikate behalten.`:''}`);
    await refreshAll();
  }catch(e){toast(e.message,true);}
}

async function pcRenewCert(id){
  const cert=data.certificates.find(c=>c.id===id);
  if(!cert)return;
  if(!confirm(`Let's-Encrypt-Zertifikat für ${cert.domain} jetzt erneuern? Port TCP 80 und HTTP-01 müssen erreichbar sein. Wiederholtes Erneuern kann zu Let's-Encrypt-Limits führen.`))return;
  try{
    await api('/certificates/'+encodeURIComponent(id)+'/renew',{method:'POST'});
    toast('Erneuerung angefordert. Bitte Jobstatus und Logs kontrollieren.');
    await refreshAll();
  }catch(e){toast(e.message,true);}
}

async function refreshUsers(){
  if(!pcIsAdmin())return;
  try{
    userRows=await api('/users');
    $('#usersRows').innerHTML=userRows.map(u=>{
      const name=esc(u.username), active=!!u.active;
      const roles=[['admin','Administrator'],['editor','Bearbeiter'],['viewer','Leser']];
      return `<tr><td><strong>${name}</strong><small>Seit ${fmtDate(u.created_at)}</small></td>
        <td><select class="user-role-select" data-user-role="${name}" aria-label="Rolle von ${name}">${roles.map(([k,label])=>`<option value="${k}" ${u.role===k?'selected':''}>${label}</option>`).join('')}</select></td>
        <td><span class="status ${active?'':'off'}">${active?'Aktiv':'Deaktiviert'}</span></td>
        <td><button type="button" class="mini-button" data-feature="resetPassword" data-username="${name}">Passwort ändern</button><button type="button" class="mini-button" data-feature="toggleUser" data-username="${name}">${active?'Deaktivieren':'Aktivieren'}</button><button type="button" class="mini-button red" data-feature="deleteUser" data-username="${name}">Löschen</button></td></tr>`;
    }).join('')||'<tr><td colspan="4">Keine Benutzer vorhanden.</td></tr>';
  }catch(e){toast(e.message,true);}
}
async function saveUserChange(username,payload){
  await api('/users/'+encodeURIComponent(username),{method:'PUT',body:JSON.stringify(payload)});
  await refreshUsers();
}

let passwordResetFor='';
function openPasswordChange(username){
  passwordResetFor=username;
  $('#passwordUsername').textContent=username;
  $('#passwordResetError').textContent='';
  $('#passwordResetForm').reset();
  $('#passwordResetOverlay').classList.remove('hidden');
  $('#passwordResetForm').querySelector('input')?.focus();
}

async function handleFeatureClick(event){
  const element=event.target.closest('[data-feature]');
  if(!element)return;
  const feature=element.dataset.feature;
  if(feature==='toggleGroup'){
    const group=element.dataset.group;
    if(collapsedDomains.has(group))collapsedDomains.delete(group);else collapsedDomains.add(group);
    renderHosts();return;
  }
  if(!pcCanWrite())return;
  if(feature==='renewCert')return pcRenewCert(element.dataset.id);
  if(feature==='replaceCert'){
    const cert=data.certificates.find(c=>c.id===element.dataset.id);
    if(cert){
      openModal('replacepem', cert.id);
    }
    return;
  }
  if(!pcIsAdmin())return;
  const username=element.dataset.username;
  const user=userRows.find(u=>u.username===username);
  if(!user)return;
  try{
    if(feature==='resetPassword')return openPasswordChange(username);
    if(feature==='toggleUser'){
      if(!confirm(`${username} ${user.active?'deaktivieren':'aktivieren'}? Bestehende Sitzungen werden gegebenenfalls beendet.`))return;
      await saveUserChange(username,{role:user.role,active:!user.active});
    }else if(feature==='deleteUser'){
      if(!confirm(`Benutzer ${username} endgültig löschen?`))return;
      await api('/users/'+encodeURIComponent(username),{method:'DELETE'});
      await refreshUsers();
    }
  }catch(e){toast(e.message,true);await refreshUsers();}
}

// Add certificate replacement as a focused supplement to the existing modal.
const _oldOpenModal=openModal;
openModal=function(kind,id=null){
  if(kind==='replacepem'){
    const cert=data.certificates.find(c=>c.id===id);
    if(!cert)return;
    modalKind='replacepem';editID=id;
    $('#modalError').textContent='';$('#modalOverlay').classList.remove('hidden');
    $('#modalTitle').textContent='PEM-Zertifikat ersetzen · '+cert.domain;
    $('#modalFields').innerHTML=`<div class="info-bar">Bestehende Domainzuweisungen bleiben erhalten. Das neue Zertifikat muss zu ${esc(cert.domain)} passen.</div>
      <label>Neue PEM-Zertifikatskette<textarea name="fullchain_pem" required placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
      <label>Neuer privater Schlüssel<textarea name="private_key_pem" required placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label>`;
    $('#saveModal').textContent='Neues Zertifikat prüfen und übernehmen';
    return;
  }
  _oldOpenModal(kind,id);
};
const _oldSaveModal=saveModal;
saveModal=async function(event){
  if(modalKind!=='replacepem')return _oldSaveModal(event);
  event.preventDefault();
  const id=editID;
  const f=new FormData(event.currentTarget);
  $('#saveModal').disabled=true;
  $('#modalError').textContent='';
  try{
    await api('/certificates/'+encodeURIComponent(id)+'/replace',{method:'POST',body:JSON.stringify({fullchain_pem:f.get('fullchain_pem'),private_key_pem:f.get('private_key_pem')})});
    closeModal();toast('PEM-Zertifikat aktualisiert; Nginx-Konfiguration wird geprüft.');await refreshAll();
  }catch(e){$('#modalError').textContent=e.message;}finally{$('#saveModal').disabled=false;}
};

$('#hostSearch')?.addEventListener('input',renderHosts);
$('#hostStatus')?.addEventListener('change',renderHosts);
$('#hostGroup')?.addEventListener('change',renderHosts);
$('#hostGroupMode')?.addEventListener('change',renderHosts);
$('#hostSelectAll')?.addEventListener('change',e=>{
  for(const host of filteredHostList){if(e.target.checked)chosenHosts.add(host.id);else chosenHosts.delete(host.id);}
  renderHosts();
});
$('#hostsRows')?.addEventListener('change',e=>{
  const id=e.target.dataset.hostId;
  if(!id)return;
  if(e.target.checked)chosenHosts.add(id);else chosenHosts.delete(id);
  renderHosts();
});
for(const [id,action] of [['bulkEnable','enable'],['bulkDisable','disable'],['bulkCategorize','categorize'],['bulkDelete','delete']]){
  $('#'+id)?.addEventListener('click',()=>pcBulkAction(action));
}
document.addEventListener('click',handleFeatureClick);
$('#createUserForm')?.addEventListener('submit',async event=>{
  event.preventDefault();
  const f=new FormData(event.currentTarget);
  const submit=event.currentTarget.querySelector('[type="submit"]');
  submit.disabled=true;
  try{
    await api('/users',{method:'POST',body:JSON.stringify({username:f.get('username'),password:f.get('password'),role:f.get('role'),active:true})});
    event.currentTarget.reset();toast('Neuer Benutzer angelegt.');await refreshUsers();
  }catch(e){toast(e.message,true);}finally{submit.disabled=false;}
});
$('#usersRows')?.addEventListener('change',async e=>{
  const username=e.target.dataset.userRole;
  if(!username)return;
  const user=userRows.find(u=>u.username===username);
  if(!user)return;
  try{await saveUserChange(username,{role:e.target.value,active:!!user.active});}
  catch(error){toast(error.message,true);await refreshUsers();}
});
$('#passwordResetCancel')?.addEventListener('click',()=>$('#passwordResetOverlay').classList.add('hidden'));
$('#passwordResetForm')?.addEventListener('submit',async e=>{
  e.preventDefault();
  const pass=new FormData(e.currentTarget).get('password');
  try{
    await api('/users/'+encodeURIComponent(passwordResetFor)+'/password',{method:'POST',body:JSON.stringify({password:pass})});
    $('#passwordResetOverlay').classList.add('hidden');e.currentTarget.reset();toast('Kennwort aktualisiert. Vorherige Sitzungen wurden beendet.');
  }catch(error){$('#passwordResetError').textContent=error.message;}
});

// bind() ran synchronously in app.js. Replace its original submit handler so
// new "replacepem" modals use the extended CSRF-protected handler.
$('#modalForm')?.removeEventListener('submit',_oldSaveModal);
$('#modalForm')?.addEventListener('submit',saveModal);

const _oldRenderStreams=renderStreams;
renderStreams=function(){
  _oldRenderStreams();
  if(!pcCanWrite()){
    $('#streamsRows')?.querySelectorAll('button[data-action]').forEach(button=>button.remove());
    $('#addStream')?.classList.add('hidden');
    $('#retryDeploy')?.classList.add('hidden');
  }else{
    $('#addStream')?.classList.remove('hidden');
    $('#retryDeploy')?.classList.remove('hidden');
  }
};

const _oldLogoutVisual=logoutVisual;
logoutVisual=function(){
  chosenHosts.clear();userRows=[];
  if($('#usersRows'))$('#usersRows').innerHTML='';
  _oldLogoutVisual();
  _oldNav('dashboard');
};
