/* ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari. */
'use strict';

/* Category tabs reuse the existing domain management list, selection and filters. */
titles.defaultpage = 'Standardseite';
let pcHostLayout = 'tiles';
let pcHealthRows = [];
let pcHealthGroup = 'all';
let pcDefaultPreviewUrl = null;

function pcGroupTabs(items, active, attribute) {
  const counts = new Map();
  items.forEach(x => counts.set(x, (counts.get(x) || 0) + 1));
  const values = [...counts.keys()].sort((a,b) => a.localeCompare(b,'de'));
  const tabs = [['all','Alle',items.length], ...values.map(g => [g,g,counts.get(g)])];
  return tabs.map(([value,label,total]) => `<button type="button" class="category-tab ${active===value?'active':''}" ${attribute}="${esc(value)}" aria-pressed="${active===value?'true':'false'}"><span>${esc(label)}</span><span class="category-count">${total}</span></button>`).join('');
}
function pcSetHostLayout(layout) {
  pcHostLayout = layout==='table' ? 'table' : 'tiles';
  $('#hostTileGrid')?.classList.toggle('hidden', pcHostLayout !== 'tiles');
  $('#hostTablePanel')?.classList.toggle('hidden', pcHostLayout !== 'table');
  for(const [id,isActive] of [['hostViewTiles',pcHostLayout==='tiles'],['hostViewTable',pcHostLayout==='table']]) {
    const button=$('#'+id);
    if(button){ button.classList.toggle('active',isActive); button.setAttribute('aria-pressed',String(isActive)); }
  }
}
function pcRenderHostTiles() {
  const all=data.hosts||[];
  const groups=all.map(h=>groupFor(h));
  const active=$('#hostGroup')?.value||'all';
  $('#hostCategoryTabs').innerHTML=pcGroupTabs(groups,active,'data-host-tab');
  const canWrite=pcCanWrite();
  const sorted=[...filteredHostList].sort((a,b)=>a.domain.localeCompare(b.domain,'de'));
  $('#hostTileGrid').innerHTML=sorted.map(h=> {
    const category=groupFor(h);
    const target=`${h.upstream_scheme}://${h.upstream_host}:${Number(h.upstream_port)}`;
    return `<article class="domain-tile ${h.enabled?'':'is-disabled'}">
      <div class="domain-tile-top"><div><div class="domain-tile-name">${esc(h.domain)}</div><small class="domain-tile-category">${esc(category)}</small></div>
      ${canWrite?`<input class="domain-tile-check" type="checkbox" data-tile-host-id="${esc(h.id)}" aria-label="${esc(h.domain)} ausw\u00e4hlen" ${chosenHosts.has(h.id)?'checked':''}>`:''}</div>
      <div class="domain-tile-address">${esc(target)}</div>
      <div class="domain-tile-footer"><span class="status ${h.enabled?'':'off'}">${h.enabled?'Aktiv':'Deaktiviert'}</span><span class="status ${h.certificate_id?'':'pending'}">${h.certificate_id?'HTTPS':'HTTP'}</span></div>
      <div class="domain-tile-actions"><button type="button" data-action="diagnoseHost" data-id="${esc(h.id)}">Vollanalyse</button>${canWrite?`<button type="button" data-action="editHost" data-id="${esc(h.id)}">Bearbeiten</button><button type="button" class="delete" data-action="deleteHost" data-id="${esc(h.id)}">L\u00f6schen</button>`:''}</div>
    </article>`;
  }).join('') || '<div class="domain-tiles-empty">Keine Domains in dieser Kategorie gefunden.</div>';
  pcSetHostLayout(pcHostLayout);
}
const pcOriginalRenderHosts=renderHosts;
renderHosts=function(){pcOriginalRenderHosts();pcRenderHostTiles();};
$('#hostCategoryTabs')?.addEventListener('click', event=> {
  const tab=event.target.closest('[data-host-tab]');
  if(!tab)return;
  $('#hostGroup').value=tab.dataset.hostTab;
  renderHosts();
});
$('#hostViewTiles')?.addEventListener('click',()=>pcSetHostLayout('tiles'));
$('#hostViewTable')?.addEventListener('click',()=>pcSetHostLayout('table'));
$('#hostTileGrid')?.addEventListener('click', actionClick);
$('#hostTileGrid')?.addEventListener('change', event=>{
  const id=event.target.dataset.tileHostId;
  if(!id)return;
  if(event.target.checked)chosenHosts.add(id);else chosenHosts.delete(id);
  renderHosts();
});

/* Monitoring uses small status chips grouped by assigned category/main domain. */
function pcHealthCategory(row) {
  if(row.type==='tcp'||row.type==='udp')return 'TCP / UDP';
  const host=(data.hosts||[]).find(h=>h.id===row.id);
  return host ? groupFor(host) : rootDomain(row.name);
}
function pcHealthState(row) {
  if(row.status==='online')return 'online';
  if(row.status==='not_tested')return 'pending';
  return 'offline';
}
function pcRenderHealthTiles() {
  const all=pcHealthRows||[];
  const groups=all.map(pcHealthCategory);
  if(pcHealthGroup!=='all'&&!groups.includes(pcHealthGroup))pcHealthGroup='all';
  $('#healthCategoryTabs').innerHTML=pcGroupTabs(groups,pcHealthGroup,'data-health-tab');
  const query=($('#healthSearch')?.value||'').trim().toLowerCase();
  const selected=all.filter(row => {
    const category=pcHealthCategory(row);
    if(pcHealthGroup!=='all'&&category!==pcHealthGroup)return false;
    return !query || (`${row.name} ${category} ${row.hint||''}`).toLowerCase().includes(query);
  });
  $('#healthCounter').textContent=`${selected.length} von ${all.length} Diensten`;
  $('#healthRows').innerHTML=selected.map(x => {
    const state=pcHealthState(x);
    const label=x.status==='online'?'Erreichbar':x.status==='not_tested'?'Nicht getestet':x.status==='tls_error'?'TLS-Fehler':x.status==='offline'?'Nicht erreichbar':x.status==='misconfigured'?'Konfiguration fehlerhaft':'Nicht verf\u00fcgbar';
    const badge=`${x.type||'http'} \u00b7 ${label}${x.code?' \u00b7 '+x.code:''}`;
    const category=pcHealthCategory(x);
    return `<article class="health-tile ${state}" title="${esc(x.hint||'')}"><div class="health-tile-name"><span class="signal"></span><strong>${esc(x.name)}</strong></div><span class="status ${state==='online'?'':state==='offline'?'off':'pending'}">${esc(badge)}</span><small>${esc(x.hint || category)}</small></article>`;
  }).join('')||'<div class="domain-tiles-empty">Keine passenden Dienste gefunden.</div>';
}
refreshMonitoring=async function(){
  try{
    pcHealthRows=await api('/healthchecks');
    pcRenderHealthTiles();
  }catch(error){
    pcHealthRows=[];
    $('#healthRows').textContent='Monitoring fehlgeschlagen: '+error.message;
    $('#healthCounter').textContent='';
    $('#healthCategoryTabs').textContent='';
  }
  await refreshLogs();
};
$('#healthCategoryTabs')?.addEventListener('click',event=>{
  const tab=event.target.closest('[data-health-tab]');
  if(!tab)return;
  pcHealthGroup=tab.dataset.healthTab;
  pcRenderHealthTiles();
});
$('#healthSearch')?.addEventListener('input',pcRenderHealthTiles);

/* Administrator can edit HTML/CSS, preview it in an opaque-origin sandbox and deploy it. */
function pcUpdateDefaultPreview() {
  const iframe=$('#defaultHtmlPreview');
  if(!iframe)return;
  if(pcDefaultPreviewUrl)URL.revokeObjectURL(pcDefaultPreviewUrl);
  const text=$('#defaultHtmlEditor').value;
  const blob=new Blob([text],{type:'text/html;charset=utf-8'});
  pcDefaultPreviewUrl=URL.createObjectURL(blob);
  iframe.src=pcDefaultPreviewUrl;
}
function pcDefaultSetMode(customized){
  $('#defaultPageMode').textContent=customized?'EIGENE SEITE':'STANDARDVORLAGE';
}
async function pcLoadDefaultPage() {
  const state=$('#defaultPageState');
  const editor=$('#defaultHtmlEditor');
  const button=$('#saveDefaultHtml');
  button.disabled=true;
  state.textContent='Lade gespeicherte Standardseite ...';
  try{
    const row=await api('/default-page');
    editor.value=row.html;
    pcDefaultSetMode(row.customized);
    pcUpdateDefaultPreview();
    state.textContent='Vorschau geladen. Speichern aktiviert die Datei nach erfolgreicher Nginx-Konfigurationspr\u00fcfung.';
    const editable=window.PC_ROLE==='admin';
    editor.readOnly=!editable;
    button.disabled=!editable;
    $('#resetDefaultHtml').disabled=!editable;
    $('#previewDefaultHtml').disabled=false;
  }catch(error){state.textContent='Standardseite konnte nicht geladen werden: '+error.message;}
}
const pcOriginalNav=nav;
nav=function(view){pcOriginalNav(view);window.scrollTo(0,0);if(view==='defaultpage')pcLoadDefaultPage();};
$('#previewDefaultHtml')?.addEventListener('click',pcUpdateDefaultPreview);
$('#saveDefaultHtml')?.addEventListener('click',async event=>{
  const button=event.currentTarget;
  button.disabled=true;
  $('#defaultPageState').textContent='Speichere und pr\u00fcfe die Nginx-Konfiguration ...';
  try{
    const result=await api('/default-page',{method:'PUT',body:JSON.stringify({html:$('#defaultHtmlEditor').value})});
    pcDefaultSetMode(true);
    pcUpdateDefaultPreview();
    const deploy=result.deployment||{};
    $('#defaultPageState').textContent=deploy.state==='error'?'Gespeichert, aber Aktivierung fehlgeschlagen: '+(deploy.message||''):'Gespeichert. Die Aktivierung wird im Hintergrund von ProxyCircuit gepr\u00fcft.';
    toast('Standardseite gespeichert; Nginx-Aktivierung angefordert.');
    await refreshDeploy();
  }catch(error){$('#defaultPageState').textContent='Fehler: '+error.message;toast(error.message,true);}
  finally{button.disabled=window.PC_ROLE!=='admin';}
});
$('#resetDefaultHtml')?.addEventListener('click',async event=>{
  if(!confirm('Eigene HTML-Seite zur\u00fccksetzen und die Standardvorlage aktivieren?'))return;
  const button=event.currentTarget;
  button.disabled=true;
  try{
    await api('/default-page/reset',{method:'POST',body:'{}'});
    await pcLoadDefaultPage();
    toast('Standardvorlage wiederhergestellt; Nginx-Aktivierung angefordert.');
  }catch(error){toast(error.message,true);}
  finally{button.disabled=window.PC_ROLE!=='admin';}
});

// Also render when the authenticated bootstrap completed unusually quickly.
if(Array.isArray(data.hosts) && data.hosts.length) renderHosts();
