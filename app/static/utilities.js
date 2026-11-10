/* ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari. */
'use strict';

/* All active operations reuse the authenticated, CSRF-protected API client. */
titles.utilities='Netzwerk-Werkzeuge';
titles.webssh='Web-SSH Terminal';
let sshSocket=null;

function closeMobileNavigation(){
  document.querySelector('.sidebar')?.classList.remove('mobile-open');
  $('#mobileBackdrop')?.classList.add('hidden');
  $('#mobileMenuButton')?.setAttribute('aria-expanded','false');
}
function showMobileNavigation(){
  document.querySelector('.sidebar')?.classList.add('mobile-open');
  $('#mobileBackdrop')?.classList.remove('hidden');
  $('#mobileMenuButton')?.setAttribute('aria-expanded','true');
}
$('#mobileMenuButton')?.addEventListener('click',()=>{
  if(document.querySelector('.sidebar')?.classList.contains('mobile-open'))closeMobileNavigation();
  else showMobileNavigation();
});
$('#mobileBackdrop')?.addEventListener('click',closeMobileNavigation);
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeMobileNavigation();});

const _utilitiesOldNav=nav;
nav=function(view){
  if(view==='webssh'&&window.PC_ROLE!=='admin')return;
  if(view!=='webssh')disconnectSsh();
  _utilitiesOldNav(view);
  closeMobileNavigation();
  if(view==='utilities')updateForwardProxyTargets();
};
const _utilitiesOldLoginVisual=loginVisual;
loginVisual=function(username,role){
  _utilitiesOldLoginVisual(username,role);
  $('#webSshNav')?.classList.toggle('hidden',role!=='admin');
  $$('.admin-utility').forEach(el=>el.classList.toggle('hidden',role!=='admin'));
};
// app.js may complete its asynchronous /api/me request before this extension loads.
// Synchronise existing session state as well as future logins.
$('#webSshNav')?.classList.toggle('hidden',window.PC_ROLE!=='admin');
$$('.admin-utility').forEach(el=>el.classList.toggle('hidden',window.PC_ROLE!=='admin'));

const _utilitiesOldLogoutVisual=logoutVisual;
logoutVisual=function(){
  disconnectSsh();closeMobileNavigation();
  _utilitiesOldLogoutVisual();
  $('#webSshNav')?.classList.add('hidden');
};

function updateForwardProxyTargets(){
  const selector=$('#forwardHostId');
  if(!selector)return;
  const current=selector.value;
  const rows=(data.hosts||[]).filter(h=>!h.domain.startsWith('*.')).sort((a,b)=>a.domain.localeCompare(b.domain,'de'));
  selector.innerHTML='<option value="">Domain auswählen</option>'+rows.map(h=>`<option value="${esc(h.id)}">${esc(h.domain)}</option>`).join('');
  if(rows.some(h=>h.id===current))selector.value=current;
}
function parsePortList(value,max){
  const ports=new Set();
  for(const raw of value.split(',')){
    const item=raw.trim();
    const m=/^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(item);
    if(!m)throw Error('Portliste: Zahlen oder Bereiche, getrennt durch Komma.');
    const a=Number(m[1]), b=m[2] ? Number(m[2]) : a;
    if(a<1||b>65535||b<a||b-a>max)throw Error('Portbereich ist ungültig oder zu groß.');
    for(let port=a;port<=b;port++)ports.add(port);
    if(ports.size>max)throw Error('Maximal '+max+' Ports pro Scan.');
  }
  if(!ports.size)throw Error('Mindestens einen Port angeben.');
  return [...ports];
}
async function runUtility(formId,endpoint,outputId,prepare){
  const form=$('#'+formId), output=$('#'+outputId), button=form?.querySelector('button[type=submit]');
  if(!form||!button)return;
  button.disabled=true;output.classList.remove('error');output.textContent='Prüfung läuft …';
  try{
    const formData=new FormData(form);
    const payload=prepare(formData);
    const result=await api('/utilities/'+endpoint,{method:'POST',body:JSON.stringify(payload)});
    output.textContent=JSON.stringify(result,null,2);
  }catch(error){output.textContent='Fehler: '+error.message;output.classList.add('error');}
  finally{button.disabled=false;}
}
for(const [form,endpoint,output,prepare] of [
  ['cidrForm','cidr','cidrOutput',f=>({cidr:f.get('cidr').trim()})],
  ['ipScanForm','ip-scan','ipScanOutput',f=>({cidr:f.get('cidr').trim(),ports:parsePortList(f.get('ports'),6)})],
  ['portScanForm','port-scan','portScanOutput',f=>({host:f.get('host').trim(),ports:parsePortList(f.get('ports'),128)})],
  ['wolForm','wake-on-lan','wolOutput',f=>({mac:f.get('mac').trim(),broadcast:f.get('broadcast').trim(),port:Number(f.get('port'))})],
  ['forwardProxyForm','forward-proxy','forwardOutput',f=>({proxy_ip:f.get('proxy_ip').trim(),proxy_port:Number(f.get('proxy_port')),host_id:f.get('host_id')})],
]){
  $('#'+form)?.addEventListener('submit',event=>{event.preventDefault();runUtility(form,endpoint,output,prepare);});
}
$('#scanMdns')?.addEventListener('click',async event=>{
  const button=event.currentTarget, output=$('#mdnsOutput');
  button.disabled=true;output.classList.remove('error');output.textContent='mDNS-Suche läuft (ca. 4 Sekunden) …';
  try{
    const result=await api('/utilities/mdns',{method:'POST',body:'{}'});
    output.textContent=JSON.stringify(result,null,2);
  }catch(error){output.textContent='Fehler: '+error.message;output.classList.add('error');}
  finally{button.disabled=false;}
});

function sshState(connected,status){
  $('#sshStatus').textContent=status;
  $('#sshDisconnect').disabled=!connected;
  $('#sshCommand').disabled=!connected;
  $('#sshSend').disabled=!connected;
  $('#sshCtrlC').disabled=!connected;
  $('#sshConnect').disabled=connected;
}
function sshAppend(raw){
  const pre=$('#sshScreen');
  // Plain-text terminal view: escape sequences are not interpreted as HTML.
  const text=String(raw).replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g,'')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/\x1b[^\[]/g,'')
    .replace(/\r(?!\n)/g,'\n').replace(/\x00/g,'');
  pre.textContent=(pre.textContent+text).slice(-160000);
  pre.scrollTop=pre.scrollHeight;
}
function disconnectSsh(){
  const ws=sshSocket;sshSocket=null;
  if(ws && ws.readyState!==WebSocket.CLOSED)ws.close(1000,'Benutzer trennt');
  sshState(false,'Getrennt');
}
function getSshData(){
  const f=new FormData($('#sshConnectForm'));
  const host=String(f.get('host')).trim(),port=Number(f.get('port'));
  if(!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)||!Number.isInteger(port)||port<1||port>65535)throw Error('SSH-Ziel-IP/Port ungültig');
  return {host,port,username:String(f.get('username')).trim(),password:String(f.get('password')),fingerprint:String(f.get('fingerprint')).trim()};
}
$('#fetchSshKey')?.addEventListener('click',async event=>{
  const button=event.currentTarget;button.disabled=true;
  try{
    const {host,port}=getSshData();
    const result=await api('/utilities/ssh/hostkey',{method:'POST',body:JSON.stringify({host,port})});
    $('#sshFingerprint').value=result.fingerprint;
    toast(result.algorithm+': '+result.fingerprint+' – Auf dem Zielserver unabhängig vergleichen!');
  }catch(error){toast(error.message,true);}finally{button.disabled=false;}
});
$('#sshConnectForm')?.addEventListener('submit',event=>{
  event.preventDefault();
  if(sshSocket&&sshSocket.readyState<=WebSocket.OPEN)return;
  let details;
  try{details=getSshData();if(!/^SHA256:[A-Za-z0-9+/]{43}$/.test(details.fingerprint))throw Error('SHA256-Hostfingerprint fehlt');}
  catch(error){toast(error.message,true);return;}
  const protocol=location.protocol==='https:'?'wss:':'ws:';
  if(protocol!=='wss:'){toast('Web-SSH nur über HTTPS erlaubt!',true);return;}
  $('#sshScreen').textContent='Verbinde zu '+details.username+'@'+details.host+':'+details.port+' …\n';
  sshState(false,'Verbindung wird aufgebaut …');
  const ws=new WebSocket(protocol+'//'+location.host+'/api/utilities/ssh/ws');
  sshSocket=ws;
  ws.onopen=()=>{
    ws.send(JSON.stringify({...details,type:'connect',csrf,cols:90,rows:25}));
    $('#sshConnectForm [name=password]').value='';
    delete details.password;
  };
  ws.onmessage=(message)=>{
    let payload;
    try{payload=JSON.parse(message.data);}catch{return;}
    if(payload.type==='ready'){
      sshState(true,'Verbunden');sshAppend('\n'+payload.message+'\n');$('#sshCommand').focus();
    }else if(payload.type==='output'){sshAppend(payload.data);}
    else if(payload.type==='error'){sshAppend('\n[Fehler] '+payload.message+'\n');}
  };
  ws.onerror=()=>{sshAppend('\n[Fehler] WebSocket-Transport nicht verfügbar. HTTPS/Reverse-Proxy-WebSocket prüfen.\n');};
  ws.onclose=()=>{if(sshSocket===ws){sshSocket=null;sshState(false,'Getrennt');}};
});
$('#sshDisconnect')?.addEventListener('click',disconnectSsh);
function sendSsh(data){
  if(sshSocket?.readyState!==WebSocket.OPEN)return;
  sshSocket.send(JSON.stringify({type:'input',data}));
}
$('#sshInputForm')?.addEventListener('submit',event=>{
  event.preventDefault();const field=$('#sshCommand');
  if(!field.disabled){sendSsh(field.value+'\n');field.value='';field.focus();}
});
$('#sshCtrlC')?.addEventListener('click',()=>sendSsh('\x03'));
window.addEventListener('beforeunload',disconnectSsh);
