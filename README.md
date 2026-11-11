# WebSentinel

Extensión Manifest V3 de inspección local para Chrome y Edge, en HTML, CSS y JavaScript, sin dependencias de ejecución, servidores ni telemetría. Los resultados proceden del documento activo o del tráfico observado; no contiene resultados predefinidos.

## Instalar

1. Abrir `chrome://extensions` o `edge://extensions`.
2. Activar **Modo de desarrollador**.
3. Elegir **Cargar descomprimida** y seleccionar esta carpeta, que contiene `manifest.json`.
4. Visitar una página HTTP/HTTPS, pulsar el icono de WebSentinel y **Analizar página**.
5. Para el panel completo, pulsar en el popup **Habilitar DevTools en este origen** y conceder el permiso específico. Abrir DevTools y seleccionar WebSentinel (puede estar en el menú de paneles adicionales).
6. Para encabezados y red: **Iniciar captura de red**, recargar el documento y esperar a que finalice su carga, **Detener captura**, después **Analizar página**. Sin respuesta principal capturada los encabezados figuran como no verificables. Abrir el panel después de abrir DevTools si no aparece inicialmente.

No funciona en páginas internas del navegador, Chrome Web Store ni documentos restringidos. Una política empresarial puede prohibir instalar extensiones desempaquetadas.

## Funciones y alcance

- DOM superior: etiquetas, jerarquía con rutas `nth-of-type`, atributos técnicos permitidos, formularios, inputs sin valores, enlaces, scripts, estilos e iframes. Buscador y resaltado temporal. Se muestran hasta 500 componentes por búsqueda; se examinan hasta 5.000.
- Tecnologías: marcadores específicos de React, Vue, Angular, Next.js; meta generator de WordPress; firmas de rutas de jQuery, Bootstrap, WordPress, Next.js y Google Analytics. Servidor/runtime declarado en encabezados. Solo Angular `ng-version` y WordPress generator proporcionan versiones declaradas; las demás quedan desconocidas. No se detecta Tailwind de forma fiable ni se infieren CVE por nombres de archivos.
- Nueve encabezados con presencia, contexto, evidencia, recomendación y referencia MDN. La presencia no demuestra eficacia. El parser CSP detecta únicamente patrones amplios, no implementa el algoritmo completo del navegador. Ausencias son recomendaciones informativas. COOP, COEP y CORP requieren adaptar la política a la integración entre orígenes.
- Patrones estáticos en scripts inline: asignación a innerHTML, document.write, eval, mensajes de depuración, referencia a source maps y asignaciones con nombres de posibles secretos. Nunca se ejecuta el código examinado. Las coincidencias se reducen a nombre de patrón, ruta DOM y línea: no se guarda el código ni el valor. Comentarios y cadenas pueden producir falsos positivos; scripts externos, comentarios HTML y mapas no se descargan ni analizan. No hay análisis de flujo ni prueba de explotación.
- HTTP en formularios, referencias mixtas e iframes sin sandbox. No se declara vulnerabilidad por su mera presencia. Los enlaces se enumeran; `target=_blank` no se considera inseguro automáticamente por las protecciones actuales de Chrome/Edge.
- Red DevTools: método, URL redactada sin query ni fragmento, estado, MIME, dominios y una lista restringida de encabezados de respuesta. No se leen cuerpos, cookies ni encabezados de solicitud. Un estado cero no demuestra error CORS. No se eluden restricciones.
- Historial de cinco informes redactados, eliminación y comparación por ID. La comparación es orientativa: cambios de orden del DOM alteran identificadores. No hay puntuación global.
- Exportación JSON y HTML independiente imprimible. Para PDF, abrir el HTML exportado y utilizar Imprimir → Guardar como PDF. El informe incluye alcance, comprobaciones, tecnologías, hallazgos, evidencia, impacto, recomendaciones, limitaciones y referencias.

## Auditoría autorizada

Activar **Auditoría autorizada**, introducir el origen exacto de la pestaña (`https://ejemplo.com`, sin barra final) y confirmar autorización. La comprobación adicional envía un único HEAD a `/`, con permiso opcional de ese origen, sin credenciales, sin seguir redirecciones y con límite de 10 segundos. Solo genera informe si la pestaña está en esa raíz sin parámetros; la respuesta HEAD no se presenta como GET. Cualquier fallo se informa como fallo. El servidor puede responder diferente a HEAD o sin sesión; los encabezados son de esa respuesta. No se hacen escaneos de rutas ni peticiones a source maps.

## Permisos y privacidad

- `activeTab`: acceso temporal a la página tras pulsar el icono.
- `scripting`: instalar el inspector aislado bajo demanda.
- `storage`: tema e informes locales.
- Orígenes **opcionales** HTTP/HTTPS: se solicita un origen concreto para DevTools o HEAD. La declaración amplia habilita solicitar distintos orígenes; no concede acceso global al instalar. Revocar en los detalles de la extensión → acceso al sitio.
- No utiliza `tabs`, `webRequest`, `debugger`, cookies, historial del navegador ni servicios externos. El API DevTools proporciona el tráfico durante una sesión explícita.

No se recopilan valores de formularios, texto visible ni atributos arbitrarios. URLs pierden credenciales, query y fragmento; se redactan segmentos largos, correos y patrones comunes de secretos. La redacción no puede identificar toda información sensible semántica en rutas cortas o encabezados permitidos: revisar antes de compartir informes. Los informes locales redactados no se cifran; la extensión no almacena claves ni secretos identificados. El almacenamiento es accesible solo a contextos de confianza de la extensión. El usuario puede borrar el historial. No hay sincronización.

La interfaz usa `textContent`, no HTML de páginas. El exportador escapa HTML. Los mensajes solo aceptan operaciones conocidas y el identificador de esta extensión. La extensión no usa eval, código remoto ni CDN; el patrón de texto `eval` solo sirve para detección. El resaltado añade un overlay temporal, no altera datos de la aplicación.

## Rendimiento y límites

Sin content scripts persistentes instalados al navegar, sondeos ni MutationObserver. El inspector inyectado queda inactivo tras cada análisis; no retiene una copia del DOM, solo referencias a hasta 5.000 nodos para resaltar. Se liberan en el siguiente análisis o al navegar. Lotes de 200, máximo 8 segundos y 500 KB de scripts inline (64 KB por script). Se informa si el DOM queda truncado. La barra indeterminada representa trabajo en curso; los recuentos son reales, no porcentajes simulados. Cancelar funciona entre lotes y fases. Una página hostil puede cambiar el DOM durante el análisis; repetir si cambia.

Captura de red: máximo 500 solicitudes o 2 minutos. Se desconecta al cerrar el panel. Los informes locales se limitan a cinco y aproximadamente 1,5 millones de caracteres entre informes; el límite es orientativo y no cifra almacenamiento. No hay animaciones continuas. El service worker solo configura el acceso al almacenamiento.

Severidad y confianza se mantienen separadas. Medio para formularios HTTP e indicios de secretos; Bajo para patrones de código y debilidades observadas; Informativo para recomendaciones contextuales. No se emiten hallazgos críticos o vulnerabilidades confirmadas porque estas comprobaciones pasivas no aportan fundamento suficiente. No se afirma que el sitio sea seguro cuando no hay hallazgos.

## Arquitectura

`content/inspector.js` extrae evidencia mínima en mundo aislado. `modules/` contiene reglas independientes y exportación. `devtools/panel.js` coordina el panel y popup compartido, permisos, cancelación y captura. `utils/` redacta y limita almacenamiento. `background/` no realiza análisis. Los módulos de reglas se importan al iniciar el análisis.

## Pruebas

Requisitos de desarrollo: Node 22+ y Chromium instalado; no se necesita instalar paquetes npm.

```sh
npm test
npm run test:browser
```

`tests/fixtures/secure.html` e `insecure.html` son páginas locales con condiciones deliberadas. No enviar sus formularios. Las cadenas de secreto son ficticias y solo existen en fixtures.

Validación ejecutada en este entorno:

- 9 pruebas de módulos: encabezados/contexto, DOM, tecnologías, riesgo conservador, redacción, minimización de red y exportación escapada.
- Chromium 156: DOM real, detección, no extracción de valores privados, cancelación entre lotes, navegación UI, tema y recuperación ante error. Estas pruebas sustituyen el puente `chrome` para probar contenido/interfaz en un servidor local.
- Se intentó cargar MV3 con línea de comandos y CDP. El navegador respondió **Loading of unpacked extensions is disabled by the administrator**. La prueba registra esta limitación y continúa con los casos de DOM/UI; no certifica integración MV3.
- **Pendiente:** instalación e integración reales en Chrome y Edge, captura HAR DevTools, permisos y exportación interactiva. No se ha ejecutado Edge aquí. Compatibilidad se basa en APIs comunes MV3, no en certificación de ambos navegadores. No se ha medido rendimiento en Intel Celeron.

Para validación manual: instalar, analizar ambos fixtures desde un servidor local, comprobar la falta de valores privados en JSON, iniciar/detener red y recargar para encabezados, cancelar en una página con muchos elementos, revocar permisos, probar una página interna, comparar historial y abrir/imprimir HTML. Los fallos deben quedar visibles, sin reutilizar un resultado como si fuera un análisis nuevo.
