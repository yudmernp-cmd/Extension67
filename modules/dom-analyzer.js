import {finding} from './risk-engine.js';
export function analyzeDOM(snapshot){const findings=[];for(const e of snapshot.elements){const a=e.attributes,loc=e.path;
 if(e.tag==='form'&&(a.action||snapshot.url).startsWith('http:'))findings.push(finding('form-http-'+e.index,'Formulario con destino HTTP','DOM',a.action||snapshot.url,loc,'Usar HTTPS en el formulario y en su destino.',{severity:'Medio',confidence:'Alta',classification:'Configuración débil'}));
 if(snapshot.url.startsWith('https:')&&['script','link','img','iframe','audio','video','source'].includes(e.tag)&&(a.src||a.href||'').startsWith('http:'))findings.push(finding('mixed-'+e.index,'Referencia a recurso HTTP desde HTTPS','DOM',a.src||a.href,loc,'Servir el recurso por HTTPS; verificar si el navegador lo bloqueó o actualizó.',{severity:'Medio',confidence:'Alta',classification:'Configuración débil'}));
 if(e.tag==='iframe'&&!('sandbox'in a))findings.push(finding('frame-'+e.index,'Iframe sin sandbox','DOM',a.src||'Iframe inline',loc,'Evaluar sandbox con los permisos mínimos necesarios.',{severity:'Bajo',classification:'Buena práctica recomendada'}));
 }return {findings,checks:3};}
