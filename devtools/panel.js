import {clean,safeURL} from '../utils/sanitizer.js';
import {saveReport,history} from '../utils/storage.js';
import {download,limitations} from '../modules/report-generator.js';
import {networkEntry} from '../modules/network-analyzer.js';
const $=id=>document.getElementById(id), dev=!!chrome.devtools?.inspectedWindow;
let allowHighlight=false, report=null, view='Resumen', running=false, cancelled=false, capturing=false, entries=[],tabId, aborter, sessionTimer;
const sections=['Resumen','Hallazgos','Componentes','Tecnologías','Encabezados','Red','Historial'];
for(const name of sections){const b=document.createElement('button');b.textContent=name;b.onclick=()=>{view=name;render();};document.querySelector('nav').append(b);}
function status(s){$('status').textContent=s;}
async function target(){if(dev){tabId=chrome.devtools.inspectedWindow.tabId;return await chrome.tabs.get(tabId);}const [t]=await chrome.tabs.query({active:true,currentWindow:true});tabId=t.id;return t;}
function element(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function table(rows){if(!rows.length)return element('p','Sin datos observados.');const t=element('table'),head=element('tr');const keys=Object.keys(rows[0]);for(const k of keys)head.append(element('th',k));t.append(head);for(const row of rows){const tr=element('tr');for(const k of keys){const td=element('td');td.textContent=typeof row[k]==='object'?JSON.stringify(row[k]):String(row[k]??'');tr.append(td);}t.append(tr);}return t;}
async function render(){const root=$('content');root.replaceChildren();for(const b of document.querySelectorAll('nav button'))b.classList.toggle('active',b.textContent===view);root.append(element('h2',view));
 if(view==='Historial'){const list=await history();for(const r of list){const a=element('article');a.append(element('p',r.url+' · '+r.date));const b=element('button','Abrir');b.onclick=()=>{report=r;allowHighlight=false;view='Resumen';render();};a.append(b);if(report&&r.url===report.url){const old=new Set(r.findings.map(f=>f.id));a.append(element('p',`Comparación por identificador: ${report.findings.filter(f=>!old.has(f.id)).length} nuevos; ${r.findings.filter(f=>!report.findings.some(n=>n.id===f.id)).length} ausentes. Cambios de DOM pueden alterar identificadores.`));}root.append(a);}const clear=element('button','Eliminar historial local');clear.onclick=async()=>{await chrome.storage.local.remove('history');render();};root.append(clear);return;}
 if(!report){root.append(element('p','Inicia un análisis para ver evidencias reales.'));return;}
 $('json').disabled=$('html').disabled=false;
 $('summary').replaceChildren();for(const severity of ['Crítico','Alto','Medio','Bajo','Informativo']){const c=element('div',undefined,'card '+severity);c.append(element('span',severity),element('strong',report.findings.filter(f=>f.severity===severity).length));$('summary').append(c);}
 const query=$('search').value.toLowerCase(), match=x=>JSON.stringify(x).toLowerCase().includes(query);
 if(view==='Resumen'){root.append(element('p',report.url),element('p',`${report.date} · ${report.status} · ${report.checks} comprobaciones · ${report.dom.processed} elementos examinados`),element('p',`${report.technologies.length} tecnologías · ${report.external.length} recursos externos · ${report.network.length} solicitudes observadas`));for(const l of report.limitations)root.append(element('p',l,'muted'));}
 if(view==='Hallazgos')for(const f of report.findings.filter(match).filter(f=>!$('severity').value||f.severity===$('severity').value)){const a=element('article');a.append(element('h3',f.severity+' · '+f.name,f.severity),element('p',f.classification+' · Confianza '+f.confidence));for(const k of ['description','evidence','location','impact','recommendation','reference'])a.append(element('p',k+': '+f[k]));root.append(a);}
 if(view==='Componentes')for(const e of report.dom.elements.filter(match).slice(0,500)){const d=element('details'),s=element('summary',e.tag+' · '+e.path);d.append(s,element('pre',JSON.stringify(e.attributes,null,2)));const b=element('button','Resaltar');b.disabled=!allowHighlight;b.onclick=async()=>{try{await chrome.tabs.sendMessage(tabId,{type:'highlight',index:e.index});}catch{status('Documento cambiado: vuelve a analizar.');}};d.append(b);root.append(d);} 
 if(view==='Tecnologías')root.append(table(report.technologies.filter(match)));
 if(view==='Encabezados')root.append(table(report.headers.filter(match)));
 if(view==='Red'){root.append(element('p','Dominios: '+JSON.stringify(report.domains)),table(report.network.filter(match)));}
}
async function analyze(extra){if(running)return;running=true;cancelled=false;$('scan').disabled=true;$('cancel').disabled=false;$('progress').hidden=false;status('Inspeccionando DOM en lotes (máximo 5.000 elementos / 8 segundos)…');
 try{const tab=await target();if(!/^https?:\/\//.test(tab.url||''))throw Error('Solo documentos HTTP/HTTPS. Si estás en DevTools, abre primero el popup y habilita el origen.');
 const origin=new URL(tab.url).origin;
 // DevTools does not confer scripting permission. Request this single origin only when required.
 if(dev&&!await chrome.permissions.contains({origins:[origin+'/*']})){
  if(!await chrome.permissions.request({origins:[origin+'/*']}))throw Error('Se requiere permiso para este origen para inspeccionar su DOM.');
 }
 await chrome.scripting.executeScript({target:{tabId},files:['content/inspector.js']});
 if(cancelled)throw Error('Análisis cancelado.');
 const snapshot=await chrome.tabs.sendMessage(tabId,{type:'scan'});if(cancelled||snapshot.cancelled)throw Error('Análisis cancelado.');if(snapshot.error)throw Error(snapshot.error);
 status(`DOM: ${snapshot.processed} elementos examinados. Evaluando evidencias…`);
 const [{analyzeDOM},{detectTechnologies},{analyzeHeaders},{analyzeCode},{detectExposure},{analyzeNetwork},{sortFindings}]=await Promise.all(['dom-analyzer','technology-detector','security-headers','code-analyzer','exposure-detector','network-analyzer','risk-engine'].map(n=>import('../modules/'+n+'.js')));
 if(cancelled)throw Error('Análisis cancelado.');
 const main=extra||[...entries].reverse().find(e=>e.resourceType==='document'&&e.url===snapshot.url),headers=analyzeHeaders(main?.headers||[],snapshot.url,!!main),dom=analyzeDOM(snapshot),code=analyzeCode(snapshot),exposure=detectExposure(snapshot),net=analyzeNetwork(entries);
 report=clean({url:snapshot.url,date:new Date().toISOString(),mode:extra?'Auditoría autorizada (HEAD)':'Inspección pasiva',scope:extra?origin:undefined,status:snapshot.truncated?'Parcial: límite de DOM alcanzado':'Completado dentro del alcance indicado',checks:dom.checks+code.checks+exposure.checks+headers.checks+net.checks,dom:snapshot,technologies:detectTechnologies(snapshot,main?.headers),headers:headers.rows,network:[...entries],domains:net.domains,external:snapshot.elements.filter(e=>{try{return new URL(e.attributes.src||e.attributes.href).origin!==origin;}catch{return false;}}).map(e=>({tag:e.tag,url:e.attributes.src||e.attributes.href})),findings:sortFindings([...dom.findings,...code.findings,...exposure.findings,...headers.findings,...net.findings]),limitations:[...limitations,snapshot.frames,...(snapshot.truncated?['DOM truncado por límite de recursos.']:[])]});
 allowHighlight=true;await saveReport(report);status(report.status);render();
 }catch(e){status(e.message||'Error de análisis.');}finally{running=false;$('scan').disabled=false;$('cancel').disabled=true;$('progress').hidden=true;}}
$('scan').onclick=()=>analyze();
$('cancel').onclick=()=>{cancelled=true;aborter?.abort();if(tabId)chrome.tabs.sendMessage(tabId,{type:'cancel'}).catch(()=>{});status('Cancelación solicitada…');};
$('search').oninput=render;$('severity').onchange=render;
$('theme').onclick=()=>{document.body.classList.toggle('light');chrome.storage.local.set({theme:document.body.classList.contains('light')?'light':'dark'});};
chrome.storage.local.get('theme').then(d=>document.body.classList.toggle('light',d.theme==='light'));
$('json').onclick=()=>download(report,'json');$('html').onclick=()=>download(report,'html');
function onRequest(entry){if(capturing){entries.push(networkEntry(entry));if(entries.length>=500)stopCapture('Límite de 500 solicitudes alcanzado.');else status(`${entries.length} solicitudes capturadas. Recarga la página para observar la respuesta principal.`);}}
function stopCapture(message='Captura detenida. Ejecuta Analizar para incorporar los datos.'){capturing=false;clearTimeout(sessionTimer);if(dev)chrome.devtools.network.onRequestFinished.removeListener(onRequest);$('capture').disabled=!dev;$('stop').disabled=true;status(message);}
$('capture').disabled=!dev;$('capture').title=dev?'Captura durante 2 minutos como máximo':'Disponible en el panel de DevTools';
$('capture').onclick=()=>{entries=[];capturing=true;chrome.devtools.network.onRequestFinished.addListener(onRequest);$('capture').disabled=true;$('stop').disabled=false;sessionTimer=setTimeout(()=>stopCapture('Sesión de red finalizada tras 2 minutos.'),120000);status('Captura activa. Recarga la página si quieres observar los encabezados del documento.');};
$('stop').onclick=()=>stopCapture();
$('authorized').onclick=()=>{$('authorization').hidden=!$('authorization').hidden;};
$('verify').onclick=async()=>{if(running)return;try{const tab=await target(),scope=new URL($('scope').value);if(scope.origin!==$('scope').value||scope.origin!==new URL(tab.url).origin||!/^https?:$/.test(scope.protocol)||!$('consent').checked)throw Error('Define el origen exacto de la página activa y confirma tu autorización.');
 if(!await chrome.permissions.request({origins:[scope.origin+'/*']}))throw Error('Permiso de origen denegado.');
 aborter=new AbortController();$('cancel').disabled=false;status('HEAD autorizado en curso; sin credenciales y sin seguir redirecciones…');const timeout=setTimeout(()=>aborter.abort(),10000);
 let response;try{response=await fetch(scope.origin+'/',{method:'HEAD',credentials:'omit',redirect:'error',cache:'no-store',signal:aborter.signal});}finally{clearTimeout(timeout);$('cancel').disabled=true;}
 if(!response.ok)throw Error('HEAD respondió '+response.status+'; no se completó la comprobación autorizada.');
 // HEAD root is not the active document: do not merge it with a different path.
 if(new URL(tab.url).pathname!=='/'||new URL(tab.url).search)throw Error('HEAD solo verificó la raíz. Abre la raíz sin parámetros para generar un informe con ese alcance.');
 await analyze({headers:[...response.headers].map(([name,value])=>({name,value})),url:safeURL(response.url)});
 }catch(e){status(e.name==='AbortError'?'HEAD cancelado o tiempo agotado.':e.message);}};
window.addEventListener('pagehide',()=>{stopCapture();aborter?.abort();if(tabId)chrome.tabs.sendMessage(tabId,{type:'cancel'}).catch(()=>{});});render();

if(!dev){const grant=element('button','Habilitar DevTools en este origen');document.querySelector('.toolbar').append(grant);grant.onclick=async()=>{try{const t=await target();const u=new URL(t.url);if(!['http:','https:'].includes(u.protocol))throw Error('Abre una página HTTP/HTTPS.');const granted=await chrome.permissions.request({origins:[u.origin+'/*']});status(granted?'Origen habilitado para DevTools. Puedes revocarlo en la configuración de la extensión.':'Permiso no concedido.');}catch(e){status(e.message);}};}
