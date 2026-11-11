export function safeURL(value) {
 try {const u=new URL(value); if(!['http:','https:'].includes(u.protocol)) return '[URL omitida]'; return u.origin+u.pathname.replace(/[A-Za-z0-9_-]{28,}/g,'[redactado]');} catch {return '[URL no disponible]';}
}
export function redact(value) {
 return String(value??'').slice(0,2000).replace(/\b(?:Bearer\s+)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]+)?/gi,'[redactado]').replace(/((?:password|passwd|secret|token|api[_-]?key|authorization|cookie)\s*[=:]\s*)[^\s;,<>]+/gi,'$1[redactado]').replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,'[correo redactado]').replace(/[A-Za-z0-9_+/=-]{32,}/g,'[redactado]');
}
export function clean(value) {
 if(Array.isArray(value)) return value.map(clean);
 if(value && typeof value==='object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k, /^(url|src|href|action)$/i.test(k)?safeURL(v):clean(v)]));
 return typeof value==='string'?redact(value):value;
}
export const escapeHTML=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
