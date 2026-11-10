// ProxyCircuit v0.1.3 Login-Hotfix | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const code = fs.readFileSync(path.join(__dirname,'../app/static/app.js'),'utf8');
const begin = code.indexOf('async function login(e) {');
const end = code.indexOf('\nasync function logout()', begin);
assert.ok(begin > 0 && end > begin, 'Login-Funktion fehlt');
const loginFunction = code.slice(begin, end);

async function simulateLogin(protocol){
  let currentTarget;
  let sent = 0, refreshed = 0, loggedIn = '', toastCalls = 0;
  const error = {textContent:''};
  const passwordField = {value:'example-secret'};
  const form = {
    querySelector: (sel)=>sel==='input[name="password"]'? passwordField:null,
    entries:{username:'admin', password:'example-secret'}
  };
  currentTarget=form;
  const ctx={
    window:{location:{protocol}},
    csrf:'',
    $: (selector)=>{assert.equal(selector,'#loginError');return error;},
    FormData:class {constructor(element){assert.equal(element,form)}get(name){return form.entries[name]}},
    api:async(path,opts)=>{
      sent++;
      assert.equal(path,'/login');
      assert.equal(opts.method,'POST');
      assert.equal(JSON.parse(opts.body).username,'admin');
      // Browser clears e.currentTarget once the dispatch finishes while we await fetch.
      currentTarget=null;
      return {username:'admin',csrf:'sample-token'};
    },
    loginVisual:(u)=>loggedIn=u,
    refreshAll:async()=>{refreshed++},
    toast:()=>toastCalls++
  };
  vm.createContext(ctx);
  vm.runInContext(loginFunction,ctx);
  const event={preventDefault(){},get currentTarget(){return currentTarget;}};
  await ctx.login(event);
  if (protocol === 'https:') {
    assert.equal(error.textContent,'');
    assert.equal(sent,1);
    assert.equal(loggedIn,'admin');
    assert.equal(passwordField.value,'');
    assert.equal(refreshed,1);
    assert.equal(ctx.csrf,'sample-token');
    assert.equal(toastCalls,0);
  } else {
    assert.equal(sent,0, 'HTTP darf keine Credentials versenden');
    assert.match(error.textContent,/HTTP gesperrt/);
    assert.equal(loggedIn,'');
    assert.equal(refreshed,0);
  }
}

(async()=>{
  await simulateLogin('https:');
  await simulateLogin('http:');
  console.log('PASS: Login verarbeitet den beendeten Event-Dispatch und sperrt HTTP.');
})().catch((err)=>{console.error(err);process.exitCode=1;});
