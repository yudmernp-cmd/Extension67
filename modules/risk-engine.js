export const severities=['Crítico','Alto','Medio','Bajo','Informativo'];
export function finding(id,name,category,evidence,location,recommendation,options={}) {
 return {id,name,category,severity:options.severity||'Informativo',confidence:options.confidence||'Media',classification:options.classification||'Posible vulnerabilidad',description:options.description||name,evidence,location,impact:options.impact||'Depende del contexto y del flujo de datos; requiere revisión manual.',recommendation,reference:options.reference||'https://owasp.org/www-project-web-security-testing-guide/'};
}
export function sortFindings(items){return items.sort((a,b)=>severities.indexOf(a.severity)-severities.indexOf(b.severity));}
