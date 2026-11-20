/* ProxyCircuit VPN v0.2.5 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org */
'use strict';
let vpnState={hub:null,sites:[],routes:[],domains:[]};
let vpnLoaded=false;
let vpnLastPreflight=null;
const vpnEsc=x=>esc(x);
const vpnAdmin=()=>window.PC_ROLE==='admin';

function vpnSelect(id,items,empty='Bitte auswählen'){
  const node=document.getElementById(id);
  if(!node)return;
  const prior=node.value;
  node.innerHTML='<option value="">'+vpnEsc(empty)+'</option>'+items.map(([v,label])=>`<option value="${vpnEsc(v)}">${vpnEsc(label)}</option>`).join('');
  if(items.some(([v])=>v===prior))node.value=prior;
}
function vpnRoutesFor(site){return vpnState.routes.filter(r=>r.site_id===site);}
function vpnUpdateRouteSelect(kind){
  const chosen=document.getElementById(kind==='new'?'vpnNewSite':'vpnBindSite')?.value||'';
  vpnSelect(kind==='new'?'vpnNewRoute':'vpnBindRoute',vpnRoutesFor(chosen).map(r=>[r.id,r.cidr]),'Privates Standortnetz auswählen');
}
function vpnCounts(){
 document.getElementById('vpnStats').innerHTML=[['Standorte',vpnState.sites.length],['Private Routen',vpnState.routes.length],['Domainbindungen',vpnState.domains.length]]
   .map(([title,value])=>`<div class="metric"><div class="metric-head">${vpnEsc(title)}</div><div class="metric-num">${value}</div><div class="metric-sub">Konfiguriert · nicht automatisch verbunden</div></div>`).join('');
}
function vpnRender(){
 const s=vpnState, h=s.hub||{};
 vpnCounts();
 const localField=document.getElementById('vpnLocalNetworks');
 if(localField)localField.value=(s.local_networks||[]).join('\n');
 for(const fld of ['interface','address','listen_port','endpoint','public_key','gateway_lan_ip']){
   const el=document.querySelector(`#vpnHubForm [name="${fld}"]`);
   if(el)el.value=h[fld]??'';
 }
 vpnSelect('vpnRouteSite',s.sites.map(x=>[x.id,x.name]));
 vpnSelect('vpnNewSite',s.sites.map(x=>[x.id,x.name]));
 vpnSelect('vpnBindSite',s.sites.map(x=>[x.id,x.name]));
 vpnSelect('vpnExistingHost',(data.hosts||[]).filter(x=>!s.domains.some(b=>b.host_id===x.id)).map(x=>[x.id,`${x.domain} → ${x.upstream_host}`]),'Bestehende Domain auswählen');
 vpnUpdateRouteSelect('new');vpnUpdateRouteSelect('bind');
 const tiles=s.sites.map(site=>{
   const siteRoutes=s.routes.filter(x=>x.site_id===site.id);
   const bindings=s.domains.filter(x=>x.site_id===site.id);
   const buttons=vpnAdmin()?`<div><button class="mini-button" data-vpn-action="edit" data-id="${vpnEsc(site.id)}">Bearbeiten</button><button class="mini-button red" data-vpn-action="delete-site" data-id="${vpnEsc(site.id)}">Löschen</button></div>`:'';
   return `<article class="vpn-site"><h3>◉ ${vpnEsc(site.name)}</h3><span class="vpn-status-chip">${site.enabled?'Konfiguriert · Tunnelstatus ungeprüft':'Standort deaktiviert'}</span>
      <p><strong>Tunnel-IP:</strong> <code>${vpnEsc(site.tunnel_ip)}</code><br><strong>Gegenstelle:</strong> ${vpnEsc(site.endpoint_host||'Dynamischer Peer')}:${Number(site.endpoint_port)}</p>
      <p><strong>Remote-Netze:</strong> ${siteRoutes.length?siteRoutes.map(r=>`<span class="status pending">${vpnEsc(r.cidr)}</span>${vpnAdmin()?` <button class="mini-button" data-vpn-action="delete-route" data-id="${vpnEsc(r.id)}" title="Route entfernen">×</button>`:''}`).join(' '):'Noch keine'}</p>
      <p><strong>VPN-Domains:</strong> ${bindings.length?bindings.map(b=>`<span class="status">${vpnEsc(b.domain)}</span> ${vpnAdmin()?`<button class="mini-button" data-vpn-action="unbind" data-id="${vpnEsc(b.host_id)}" title="Nur Bindung lösen">×</button>`:''}`).join(' '):'Noch keine'}</p>${buttons}</article>`;
 }).join('');
 document.getElementById('vpnSites').innerHTML=tiles||'<p class="vpn-muted">Noch keine Standorte. Zuerst den Hub vorbereiten, dann Remote-Gateways anlegen.</p>';
 document.getElementById('vpnWarnings').textContent='Nur Konfigurationsverwaltung. Der WireGuard-Tunnel ist weder gestartet noch auf Erreichbarkeit geprüft. VPN-Domains werden zunächst deaktiviert angelegt.';
 document.querySelectorAll('.vpn-admin-only').forEach(el=>el.classList.toggle('hidden',!vpnAdmin()));
}
async function vpnLoad(){
 try{vpnState=await api('/vpn/overview');vpnLoaded=true;vpnRender();if(vpnAdmin())await vpnRunPreflight();}
 catch(err){document.getElementById('vpnWarnings').textContent='VPN-Daten konnten nicht geladen werden: '+err.message;}
}
async function vpnRunPreflight(){
  if(!vpnAdmin())return;
  const output=document.getElementById('vpnPreflightIssues');
  const summary=document.getElementById('vpnPreflightSummary');
  const chip=document.getElementById('vpnPreflightChip');
  summary.textContent='Konfiguration wird ohne Netzwerkzugriff geprüft …';
  try{
    const report=await api('/vpn/preflight');
    vpnLastPreflight=report;
    const blocked=report.blockers>0;
    chip.textContent=blocked?'Blockiert':report.warnings?'Prüfung erforderlich':'Bereit für Gateway-Test';
    chip.classList.toggle('vpn-preflight-ok',!blocked && !report.warnings);
    summary.textContent=`${report.blockers} Blocker · ${report.warnings} Warnungen · Plan SHA256 ${report.config_sha256.slice(0,16)}…`;
    output.innerHTML=report.checks.length?report.checks.map(item=>
       `<div class="vpn-check vpn-check-${vpnEsc(item.level)}"><strong>${vpnEsc(item.level==='blocker'?'Blocker':item.level==='warning'?'Hinweis':'Info')}</strong><span>${vpnEsc(item.detail)}</span></div>`
    ).join(''):'<div class="vpn-check vpn-check-info">Keine statischen Konfigurationsprobleme erkannt. Echter Tunnel noch nicht geprüft.</div>';
    document.getElementById('vpnExportPreflight').disabled=false;
  }catch(err){vpnLastPreflight=null;summary.textContent=err.message;chip.textContent='Prüfung fehlgeschlagen';output.textContent='';document.getElementById('vpnExportPreflight').disabled=true;}
}
function vpnFormData(id){return Object.fromEntries(new FormData(document.getElementById(id)).entries());}
async function vpnSubmit(id,route,mapper){
 const form=document.getElementById(id);
 form.addEventListener('submit',async(e)=>{
   e.preventDefault();if(!vpnAdmin())return;
   try{
     const values=vpnFormData(id);
     const [path,method,payload]=route(values);
     await api(path,{method,body:JSON.stringify(mapper?mapper(payload):payload)});
     toast('VPN-Einstellung gespeichert. Kein aktiver Tunnel wurde verändert.');
     if(id==='vpnSiteForm'){form.reset();form.querySelector('[name="site_id"]').value='';document.getElementById('vpnSiteSave').textContent='Standort speichern';}
     if(id==='vpnRouteForm'||id==='vpnNewDomainForm'||id==='vpnBindForm')form.reset();
     await vpnLoad();
     if(id==='vpnNewDomainForm'){await refreshAll();await vpnLoad();}
   }catch(err){toast(err.message,true);}
 });
}
function vpnDownload(filename,text){
 const blob=new Blob([text],{type:'application/json'});
 const url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function vpnBind(){
 document.getElementById('vpnLocalNetworksForm').addEventListener('submit',async(e)=>{
   e.preventDefault();if(!vpnAdmin())return;
   const entries=document.getElementById('vpnLocalNetworks').value.split(/\r?\n|,/).map(x=>x.trim()).filter(Boolean);
   try{
     await api('/vpn/local-networks',{method:'PUT',body:JSON.stringify({networks:entries})});
     toast('Lokale Netze gespeichert; keine aktiven Routen verändert.');await vpnLoad();
   }catch(err){toast(err.message,true);}
 });
 document.getElementById('vpnRunPreflight').addEventListener('click',vpnRunPreflight);
 document.getElementById('vpnExportPreflight').addEventListener('click',()=>{
   if(vpnLastPreflight)vpnDownload('proxycircuit-vpn-preflight-v0.2.5.json',JSON.stringify(vpnLastPreflight,null,2));
 });
 vpnSubmit('vpnHubForm',v=>['/vpn/hub','PUT',v],v=>({...v,listen_port:Number(v.listen_port)}));
 vpnSubmit('vpnSiteForm',v=>[v.site_id?'/vpn/sites/'+encodeURIComponent(v.site_id):'/vpn/sites',v.site_id?'PUT':'POST',v],v=>({
    name:v.name,public_key:v.public_key.trim(),tunnel_ip:v.tunnel_ip.trim(),endpoint_host:v.endpoint_host.trim(),
    endpoint_port:Number(v.endpoint_port),keepalive:Number(v.keepalive),enabled:v.enabled==='on'
 }));
 vpnSubmit('vpnRouteForm',v=>['/vpn/sites/'+encodeURIComponent(v.site_id)+'/routes','POST',{cidr:v.cidr}]);
 vpnSubmit('vpnNewDomainForm',v=>['/vpn/domains','POST',v],v=>({...v,target_port:Number(v.target_port)}));
 vpnSubmit('vpnBindForm',v=>['/vpn/bindings','POST',v]);
 document.getElementById('vpnNewSite').addEventListener('change',()=>vpnUpdateRouteSelect('new'));
 document.getElementById('vpnBindSite').addEventListener('change',()=>vpnUpdateRouteSelect('bind'));
 document.getElementById('vpnSites').addEventListener('click',async e=>{
  const button=e.target.closest('[data-vpn-action]');if(!button||!vpnAdmin())return;
  const action=button.dataset.vpnAction,id=button.dataset.id;
  if(action==='edit'){
    const site=vpnState.sites.find(s=>s.id===id);if(!site)return;
    const form=document.getElementById('vpnSiteForm');
    Object.entries(site).forEach(([k,v])=>{const el=form.elements.namedItem(k);if(el){if(el.type==='checkbox')el.checked=!!v;else el.value=v;}});
    form.elements.namedItem('site_id').value=id;
    document.getElementById('vpnSiteSave').textContent='Standort aktualisieren';
    form.scrollIntoView({behavior:'smooth',block:'center'});return;
  }
  const url=action==='delete-site'?'/vpn/sites/'+encodeURIComponent(id):action==='delete-route'?'/vpn/routes/'+encodeURIComponent(id):'/vpn/bindings/'+encodeURIComponent(id);
  if(!confirm(action==='unbind'?'Nur VPN-Bindung lösen? Die bestehende Proxy-Domain bleibt erhalten.':'VPN-Eintrag entfernen? Aktive WireGuard-Gateways werden NICHT geändert.'))return;
  try{await api(url,{method:'DELETE'});toast('Eintrag entfernt (nur in ProxyCircuit).');await vpnLoad();}catch(err){toast(err.message,true);}
 });
 document.getElementById('vpnPreview').addEventListener('click',async()=>{
   try{const res=await api('/vpn/preview');document.getElementById('vpnPreviewText').textContent=res.template;}
   catch(err){toast(err.message,true);}
 });
 document.getElementById('vpnExport').addEventListener('click',async()=>{
   try{const result=await api('/vpn/export');vpnDownload('proxycircuit-wireguard-plan.json',JSON.stringify(result,null,2));toast('Export ohne private Schlüssel heruntergeladen.');}
   catch(err){toast(err.message,true);}
 });
 document.getElementById('vpnResetSite').addEventListener('click',()=>{
   const form=document.getElementById('vpnSiteForm');form.reset();form.elements.namedItem('site_id').value='';
   document.getElementById('vpnSiteSave').textContent='Standort speichern';
 });
}
const vpnOldNav=nav;
nav=function(v){vpnOldNav(v);if(v==='vpn')vpnLoad();};
window.addEventListener('DOMContentLoaded',vpnBind);
