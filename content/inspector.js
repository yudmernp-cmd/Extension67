// Isolated world, only installed on demand. No form values, text nodes or arbitrary attributes leave the page.
(()=>{
 const key='__webSentinelInspector'; if(globalThis[key]) return;
 let cancelled=false, nodes=[], timer, overlay;
 const url=v=>{try{const u=new URL(v,location.href);return ['http:','https:'].includes(u.protocol)?u.origin+u.pathname.replace(/[A-Za-z0-9_-]{28,}/g,'[redactado]'):'[URL omitida]';}catch{return '[URL inválida]';}};
 const path=e=>{let parts=[];while(e&&parts.length<12){let n=1,s=e;while((s=s.previousElementSibling))if(s.tagName===e.tagName)n++;parts.unshift(e.localName+':nth-of-type('+n+')');e=e.parentElement;}return parts.join(' > ');};
 const remove=()=>{overlay?.remove();overlay=null;clearTimeout(timer);};
 globalThis[key]=true;
 chrome.runtime.onMessage.addListener((m,s,reply)=>{
  if(s.id!==chrome.runtime.id || !m || !['scan','cancel','highlight'].includes(m.type))return;
  if(m.type==='cancel'){cancelled=true;nodes=[];remove();reply({ok:true});return;}
  if(m.type==='highlight'){remove();const e=nodes[m.index];if(e?.isConnected){const b=e.getBoundingClientRect();overlay=document.createElement('div');overlay.style.cssText=`position:fixed;pointer-events:none;z-index:2147483647;border:2px solid #32c7ae;background:#32c7ae22;left:${b.x}px;top:${b.y}px;width:${b.width}px;height:${b.height}px`;document.documentElement.append(overlay);timer=setTimeout(remove,1800);}reply({ok:true});return;}
  cancelled=false;nodes=[];
  (async()=>{
   const start=performance.now(), walker=document.createTreeWalker(document.documentElement,NodeFilter.SHOW_ELEMENT), elements=[],scripts=[],markers=new Set();let e=document.documentElement, processed=0, bytes=0;
   while(e&&processed<5000&&performance.now()-start<8000){
    if(cancelled){reply({cancelled:true});return;}
    const tag=e.localName, index=nodes.push(e)-1, attrs={};
    for(const k of ['type','method','target','rel','sandbox','integrity','crossorigin','http-equiv'])if(e.hasAttribute(k))attrs[k]=e.getAttribute(k).slice(0,160);
    for(const k of ['src','href','action'])if(e.hasAttribute(k))attrs[k]=url(e.getAttribute(k));
    elements.push({index,tag,path:path(e),attributes:attrs});
    if(e.hasAttribute('data-reactroot')||Object.keys(e).some(k=>k.startsWith('__reactFiber$')))markers.add('React');
    if(e.hasAttribute('data-v-app')||e.__vueParentComponent)markers.add('Vue');
    if(e.hasAttribute('ng-version'))markers.add('Angular '+e.getAttribute('ng-version').replace(/[^0-9.]/g,'').slice(0,30));
    if(e.id==='__NEXT_DATA__')markers.add('Next.js');
    if(tag==='meta'&&e.name==='generator')markers.add('generator:'+e.content.slice(0,100));
    if(tag==='script'&&!e.src&&bytes<500000){const text=e.textContent.slice(0,Math.min(64000,500000-bytes));bytes+=text.length;const patterns=[];
     for(const [name,re] of [['innerHTML',/\.innerHTML\s*=/],['document.write',/document\.write\s*\(/],['eval',/\beval\s*\(/],['sourceMappingURL',/sourceMappingURL\s*=/],['debug',/console\.(?:log|debug)\s*\(/],['posible secreto',/(?:api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"']{8,}["']/i]]){const hit=re.exec(text);if(hit)patterns.push({name,line:text.slice(0,hit.index).split('\n').length});}
     scripts.push({location:path(e),patterns});
    }
    processed++;e=walker.nextNode();if(processed%200===0)await new Promise(r=>setTimeout(r,0));
   }
   reply({url:url(location.href),elements,scripts,markers:[...markers],processed,truncated:!!e,inlineBytes:bytes,limits:{elements:5000,milliseconds:8000,inlineBytes:500000},frames:'Solo documento superior; no shadow DOM cerrado ni documentos de iframes.'});
  })().catch(()=>reply({error:'No se pudo inspeccionar el documento.'}));return true;
 });
})();
