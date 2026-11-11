import {finding} from './risk-engine.js';
export const policies={
 'content-security-policy':['Restringe los orígenes de ejecución y recursos.',"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"],
 'strict-transport-security':['Obliga a usar HTTPS en visitas posteriores.','max-age=31536000'],
 'x-frame-options':['Controla quién puede embeber la página.','DENY'],
 'x-content-type-options':['Evita interpretar recursos con un MIME diferente.','nosniff'],
 'referrer-policy':['Limita la información del referente.','strict-origin-when-cross-origin'],
 'permissions-policy':['Restringe funciones del navegador.','camera=(), microphone=(), geolocation=()'],
 'cross-origin-resource-policy':['Limita inclusión de recursos por otros orígenes.','same-origin'],
 'cross-origin-opener-policy':['Aísla grupos de contextos de navegación.','same-origin'],
 'cross-origin-embedder-policy':['Exige autorización para recursos entre orígenes.','require-corp']};
export function analyzeHeaders(headers,url,observed=false){
 if(!observed)return {rows:Object.keys(policies).map(name=>({name,status:'No verificable: respuesta principal no capturada'})),findings:[],checks:0};
 const map={};for(const h of headers){const k=h.name.toLowerCase();map[k]=map[k]?map[k]+', '+h.value:h.value;}
 const rows=[],findings=[];
 for(const [name,[description,recommendation]]of Object.entries(policies)){
 const value=map[name], reference='https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/'+name;
 let weak=false,why='';
 if(value){
  if(name==='content-security-policy'&&(/'unsafe-(?:inline|eval)'/.test(value)||/(?:^|;)\s*(?:default|script)-src\s+[^;]*\*/.test(value))){weak=true;why='Permite ejecución inline, eval o fuentes amplias; evaluar nonces y hashes.';}
  if(name==='strict-transport-security'&&(!/max-age\s*=\s*[1-9]\d*/i.test(value)||!url.startsWith('https:'))){weak=true;why='max-age no positivo o respuesta sin HTTPS.';}
  if(name==='x-content-type-options'&&value.toLowerCase()!=='nosniff'){weak=true;why='Valor diferente de nosniff.';}
  if(name==='x-frame-options'&&!/^(deny|sameorigin)$/i.test(value)){weak=true;why='Valor no reconocido.';}
  if(name==='referrer-policy'&&/^(unsafe-url|no-referrer-when-downgrade)$/i.test(value)){weak=true;why='Puede revelar información del referente.';}
 }
 const applicable=!(name==='strict-transport-security'&&!url.startsWith('https:'));
 rows.push({name,value:value||'Ausente',status:!applicable?'No aplicable en HTTP':weak?'Revisar':value?'Presente; no garantiza eficacia':'Ausente; evaluar contexto',description,recommendation,reference});
 if((!value&&applicable)||weak)findings.push(finding('header-'+name,weak?'Revisar '+name:'Evaluar '+name,'HTTP',value||'Ausente en respuesta observada',url,recommendation+' — adaptar a la aplicación.',{severity:weak?'Bajo':'Informativo',confidence:'Alta',classification:weak?'Configuración débil':'Buena práctica recomendada',description:why||description,reference}));
 }return {rows,findings,checks:rows.length};}
