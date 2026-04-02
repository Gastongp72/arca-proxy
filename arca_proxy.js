/**
 * arca_proxy.js — Proxy local para webservices ARCA (ex AFIP)
 *
 * Uso: node arca_proxy.js
 * Puerto: 3838 (configurable con PORT=xxxx)
 *
 * Endpoints:
 *   POST /api/padron        → WSpadron5: consulta contribuyente por CUIT
 *   POST /api/padron/batch  → WSpadron5: validación masiva de CUITs
 *   POST /api/fe/ultimo     → WSFEv1: último comprobante autorizado
 *   POST /api/fe/autorizar  → WSFEv1: solicitar CAE
 *   POST /api/test          → Prueba de conexión
 *
 *   === Leaf Agriculture (FieldView) ===
 *   POST /api/leaf/login        → Autenticar con Leaf y obtener JWT
 *   POST /api/leaf/fields       → Obtener campos/lotes del usuario
 *   POST /api/leaf/operations   → Obtener operaciones de un campo
 *   POST /api/leaf/cfv/connect  → Vincular Climate FieldView
 *
 * Requiere: Node.js (solo módulos nativos: http, https, crypto)
 * No necesita npm install — usa http nativo + openssl del sistema
 *
 * ARCA CUIT consultante: 30-70857746-0 (González del Pino SRL)
 */

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const pathMod = require("path");
const { URL } = require("url");

const PORT = process.env.PORT || 3838;
const BASE_DIR = __dirname; // carpeta donde está arca_proxy.js y erp_tango.html

// MIME types para servir archivos estáticos
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

// ============================================================================
// WSDL URLs
// ============================================================================
const WSAA_WSDL = {
  testing: "https://wsaahomo.afip.gov.ar/ws/services/LoginCms?WSDL",
  production: "https://wsaa.afip.gov.ar/ws/services/LoginCms?WSDL",
};
const WSAA_URL = {
  testing: "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
  production: "https://wsaa.afip.gov.ar/ws/services/LoginCms",
};
const PADRON5_URL = {
  testing: "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL",
  production: "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL",
};
const PADRON5_SOAP_URL = {
  testing: "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5",
  production: "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5",
};
const WSFE_URL = {
  testing: "https://wswhomo.afip.gov.ar/wsfev1/service.asmx",
  production: "https://servicios1.afip.gov.ar/wsfev1/service.asmx",
};

// ============================================================================
// TOKEN CACHE
// ============================================================================
const tokenCache = {}; // { [service_entorno]: { token, sign, expira } }

// ============================================================================
// HELPERS
// ============================================================================
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
    });
    req.on("error", reject);
  });
}

function respond(res, status, body) {
  if (res.writableEnded || res.headersSent) return;
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(JSON.stringify(body));
}

function soapRequest(url, soapBody, soapAction) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const headers = {
      "Content-Type": "text/xml; charset=utf-8",
      "Content-Length": Buffer.byteLength(soapBody),
    };
    if (soapAction !== undefined) {
      headers["SOAPAction"] = `"${soapAction}"`;
    }
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: "POST",
      headers,
            ciphers: "DEFAULT:@SECLEVEL=0",
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve(data));
    });
    req.on("error", reject);
    req.write(soapBody);
    req.end();
  });
}

// ============================================================================
// WSAA — Login CMS (obtener token/sign para un servicio)
// ============================================================================
function createCMS(cert_pem, key_pem, service, entorno) {
  const now = new Date();
  const expira = new Date(now.getTime() + 600000); // 10 min
  const tra = `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${Math.floor(now.getTime() / 1000)}</uniqueId>
    <generationTime>${now.toISOString()}</generationTime>
    <expirationTime>${expira.toISOString()}</expirationTime>
  </header>
  <service>${service}</service>
</loginTicketRequest>`;

  // Firmar TRA con PKCS#7 (CMS)
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(tra);
  const signature = sign.sign(key_pem, "base64");

  // Construir estructura CMS simplificada usando openssl-compatible approach
  // ARCA requiere PKCS#7 SignedData. Usamos child_process para invocar openssl.
  return { tra, signature, expira };
}

async function loginCMS(cert_pem, key_pem, service, entorno) {
  const cacheKey = `${service}_${entorno}`;
  const cached = tokenCache[cacheKey];
  if (cached && new Date(cached.expira) > new Date()) {
    console.log(`[WSAA] Token cacheado para ${service} (${entorno})`);
    return { token: cached.token, sign: cached.sign };
  }

  console.log(`[WSAA] Solicitando nuevo token para ${service} (${entorno})...`);

  // Usar openssl para crear CMS firmado (PKCS#7)
  const { execSync } = require("child_process");
  const os = require("os");

  const tmpDir = os.tmpdir();
  const certFile = pathMod.join(tmpDir, "arca_cert.pem");
  const keyFile = pathMod.join(tmpDir, "arca_key.pem");
  const traFile = pathMod.join(tmpDir, "arca_tra.xml");
  const cmsFile = pathMod.join(tmpDir, "arca_cms.p7");

  const now = new Date();
  const expira = new Date(now.getTime() + 600000);
  const tra = `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${Math.floor(now.getTime() / 1000)}</uniqueId>
    <generationTime>${now.toISOString()}</generationTime>
    <expirationTime>${expira.toISOString()}</expirationTime>
  </header>
  <service>${service}</service>
</loginTicketRequest>`;

  fs.writeFileSync(certFile, cert_pem);
  fs.writeFileSync(keyFile, key_pem);
  fs.writeFileSync(traFile, tra);

  try {
    execSync(
      `openssl smime -sign -signer "${certFile}" -inkey "${keyFile}" -outform DER -nodetach -in "${traFile}" -out "${cmsFile}"`,
      { timeout: 15000 }
    );
  } catch (err) {
    throw new Error("Error al firmar TRA con openssl: " + (err.stderr?.toString() || err.message));
  }

  const cms = fs.readFileSync(cmsFile).toString("base64");

  // Llamar WSAA
  const wsaaUrl = WSAA_URL[entorno] || WSAA_URL.testing;
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov">
  <soapenv:Body>
    <wsaa:loginCms>
      <wsaa:in0>${cms}</wsaa:in0>
    </wsaa:loginCms>
  </soapenv:Body>
</soapenv:Envelope>`;

  const response = await soapRequest(wsaaUrl, soapBody, "");
  console.log(`[WSAA] Respuesta para ${service} (primeros 800 chars): ${response.substring(0, 800)}`);

  // Guardar respuesta para debug
  try { fs.writeFileSync(pathMod.join(BASE_DIR, `debug_wsaa_${service}.xml`), response); } catch(e) {}

  // Parsear respuesta — buscar token/sign con regex flexible (puede estar escapado como XML entities)
  let tokenMatch = response.match(/<token>([^<]+)<\/token>/);
  let signMatch = response.match(/<sign>([^<]+)<\/sign>/);

  // Si no encuentra, intentar dentro de loginCmsReturn que puede tener el XML escapado
  if (!tokenMatch) {
    const returnMatch = response.match(/<loginCmsReturn>([^]*?)<\/loginCmsReturn>/);
    if (returnMatch) {
      const inner = returnMatch[1].replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&quot;/g, '"');
      console.log(`[WSAA] loginCmsReturn decodificado: ${inner.substring(0, 500)}`);
      tokenMatch = inner.match(/<token>([^<]+)<\/token>/);
      signMatch = inner.match(/<sign>([^<]+)<\/sign>/);
    }
  }

  if (!tokenMatch || !signMatch) {
    const faultMatch = response.match(/<faultstring>([^<]+)<\/faultstring>/);
    throw new Error("WSAA login falló: " + (faultMatch ? faultMatch[1] : "Respuesta inesperada"));
  }

  const result = { token: tokenMatch[1], sign: signMatch[1] };
  tokenCache[cacheKey] = { ...result, expira: expira.toISOString() };
  console.log(`[WSAA] Token obtenido para ${service}, expira: ${expira.toISOString()}`);

  // Limpiar archivos temporales
  try { fs.unlinkSync(certFile); fs.unlinkSync(keyFile); fs.unlinkSync(traFile); fs.unlinkSync(cmsFile); } catch {}

  return result;
}

// ============================================================================
// WSpadron5 — Consulta de contribuyente
// ============================================================================
async function consultarPadron(cuit_consultante, cuit_consulta, token, sign, entorno, servicio) {
  const url = PADRON5_SOAP_URL[entorno] || PADRON5_SOAP_URL.testing;

  // ws_sr_constancia_inscripcion usa getPersona_v2, los demás usan getPersona
  const useV2 = servicio === "ws_sr_constancia_inscripcion";
  const method = useV2 ? "getPersona_v2" : "getPersona";
  const soapAction = useV2 ? "http://a5.soap.ws.server.puc.sr/getPersona_v2" : "http://a5.soap.ws.server.puc.sr/getPersona";

  console.log(`[PADRON-SOAP] Llamando ${method} en ${url} para CUIT ${cuit_consulta} (servicio: ${servicio || "a5"})`);

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a5="http://a5.soap.ws.server.puc.sr/">
  <soapenv:Body>
    <a5:${method}>
      <token>${token}</token>
      <sign>${sign}</sign>
      <cuitRepresentada>${cuit_consultante}</cuitRepresentada>
      <idPersona>${cuit_consulta}</idPersona>
    </a5:${method}>
  </soapenv:Body>
</soapenv:Envelope>`;

  const response = await soapRequest(url, soapBody, soapAction);
  console.log(`[PADRON-SOAP] Respuesta (primeros 500 chars): ${response.substring(0, 500)}`);

  // Verificar si hay fault
  const faultMatch = response.match(/<faultstring>([^<]*)<\/faultstring>/);
  if (faultMatch) {
    return { ok: false, error: faultMatch[1], source: "arca-wspadron5" };
  }

  // Parsear datos
  const extract = (tag) => {
    const m = response.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
    return m ? m[1] : "";
  };
  const extractAll = (tag) => {
    const matches = [];
    const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, "g");
    let m;
    while ((m = re.exec(response)) !== null) matches.push(m[1]);
    return matches;
  };

  // Tipo persona
  const tipoPersona = extract("tipoPersona");
  let razon_social = "";
  if (tipoPersona === "JURIDICA") {
    razon_social = extract("razonSocial");
  } else {
    const nombre = extract("nombre");
    const apellido = extract("apellido");
    razon_social = `${apellido}, ${nombre}`.replace(/^, |, $/g, "");
  }

  // Estado
  const estadoCuit = extract("estadoClave") || extract("estado");

  // Domicilio fiscal
  const domParts = [];
  const direccion = extract("direccion");
  const localidad = extract("localidad");
  const provincia = extract("descripcionProvincia") || extract("idProvincia");
  const codPostal = extract("codPostal");
  if (direccion) domParts.push(direccion);
  if (localidad) domParts.push(localidad);
  if (provincia) domParts.push(provincia);
  if (codPostal) domParts.push(`CP ${codPostal}`);

  // Condición IVA
  const impuestos = extractAll("idImpuesto");
  const estados = extractAll("estado");
  // IVA = impuesto 30, Monotributo = 20
  let condicion_iva = "CF"; // Consumidor Final por defecto
  const ivaIdx = impuestos.indexOf("30");
  if (ivaIdx >= 0 && estados[ivaIdx] === "ACTIVO") {
    condicion_iva = "RI"; // Responsable Inscripto
  }
  const monoIdx = impuestos.indexOf("20");
  if (monoIdx >= 0 && estados[monoIdx] === "ACTIVO") {
    condicion_iva = "M"; // Monotributista
  }
  // Exento
  const exentoIdx = impuestos.indexOf("32");
  if (exentoIdx >= 0 && estados[exentoIdx] === "ACTIVO") {
    condicion_iva = "EX";
  }

  // Actividades
  const actividades = extractAll("idActividad");
  const actDescripciones = extractAll("descripcionActividad");

  return {
    ok: true,
    source: "arca-wspadron5",
    cuit: cuit_consulta,
    razon_social,
    tipo_persona: tipoPersona,
    estado_cuit: estadoCuit,
    condicion_iva,
    direccion: domParts.join(", "),
    domicilio: domParts.join(", "),
    localidad: localidad || "",
    provincia: provincia || "",
    cod_postal: codPostal || "",
    actividades: actividades.map((id, i) => ({ id, descripcion: actDescripciones[i] || "" })),
  };
}

// ============================================================================
// CONSULTA PÚBLICA DE PADRÓN (fallback sin ws_sr_padron_a5)
// ============================================================================

// Helper: HTTPS GET/POST que devuelve { statusCode, headers, body }
function httpsReq(options, postData) {
  return new Promise((resolve) => {
    try {
      const req = https.request(options, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
        res.on("error", () => resolve({ statusCode: 0, headers: {}, body: "" }));
      });
      const timer = setTimeout(() => { try { req.destroy(); } catch(e) {} resolve({ statusCode: 0, headers: {}, body: "Timeout 15s" }); }, 15000);
      req.on("error", (err) => { clearTimeout(timer); resolve({ statusCode: 0, headers: {}, body: err.message }); });
      if (postData) req.write(postData);
      req.end();
    } catch (err) {
      resolve({ statusCode: 0, headers: {}, body: err.message });
    }
  });
}

// Fuente 1: CuitOnline (scraping HTML, muy confiable)
async function consultarCuitOnline(cuit) {
  console.log(`[PADRON-CUITONLINE] Consultando CUIT ${cuit}...`);
  try {
    const res = await httpsReq({
      hostname: "www.cuitonline.com",
      path: `/constancia/inscripcion/${cuit}`,
      method: "GET",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept": "text/html" },
    });
    console.log(`[PADRON-CUITONLINE] HTTP ${res.statusCode}, largo: ${res.body.length}`);
    const html = res.body;

    if (res.statusCode !== 200) return { ok: false, error: `HTTP ${res.statusCode}` };

    // Guardar para debug
    try { fs.writeFileSync(pathMod.join(BASE_DIR, "debug_cuitonline.html"), html); } catch(e) {}

    // Extraer razón social — CuitOnline usa <h4> o <div class="denominacion">
    let razon_social = "";
    const rzPatterns = [
      /<h4[^>]*>([^<]+)<\/h4>/i,
      /class="[^"]*denominacion[^"]*"[^>]*>([^<]+)/i,
      /Denominaci[oó]n[^<]*<[^>]*>([^<]+)/i,
      /Raz[oó]n\s*Social[^<]*<[^>]*>([^<]+)/i,
      /Apellido\s*y\s*Nombre[^<]*<[^>]*>([^<]+)/i,
      /<title>([^<]+?)[\s-]*CUIT/i,
    ];
    for (const p of rzPatterns) {
      const m = html.match(p);
      if (m && m[1].trim().length > 2 && !m[1].includes("CUIT Online") && !m[1].includes("Constancia")) {
        razon_social = m[1].trim();
        break;
      }
    }

    if (!razon_social) return { ok: false, error: "No se encontró razón social en CuitOnline" };

    // Condición IVA
    let condicion_iva = "CF";
    const ivaMatch = html.match(/IVA[^<]*<[^>]*>([^<]+)/i)
      || html.match(/Responsable\s*Inscripto/i)
      || html.match(/Monotributo/i)
      || html.match(/Exento/i);
    if (ivaMatch) {
      const t = (ivaMatch[1] || ivaMatch[0]).toUpperCase();
      if (t.includes("INSCRIPTO")) condicion_iva = "RI";
      else if (t.includes("MONOTRIBUTO")) condicion_iva = "M";
      else if (t.includes("EXENTO")) condicion_iva = "EX";
    }

    // Domicilio
    let domicilio = "";
    const domMatch = html.match(/Direcci[oó]n[^<]*<[^>]*>([^<]+)/i) || html.match(/Domicilio[^<]*<[^>]*>([^<]+)/i);
    if (domMatch) domicilio = domMatch[1].trim();

    let localidad = "", provincia = "";
    const locMatch = html.match(/Localidad[^<]*<[^>]*>([^<]+)/i);
    if (locMatch) localidad = locMatch[1].trim();
    const provMatch = html.match(/Provincia[^<]*<[^>]*>([^<]+)/i);
    if (provMatch) provincia = provMatch[1].trim();

    return { ok: true, source: "cuitonline", cuit, razon_social, condicion_iva, domicilio, localidad, provincia, estado_cuit: "ACTIVO" };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// Fuente 2: Scraping ARCA constancia (con sesión y cookies)
async function consultarConstanciaARCA(cuit) {
  console.log(`[PADRON-ARCA] Consultando CUIT ${cuit}...`);
  try {
    // Paso 1: GET página principal para cookie de sesión
    const res1 = await httpsReq({
      hostname: "seti.afip.gob.ar",
      path: "/padron-puc-constancia-internet/ConsultaConstanciaAction.do",
      method: "GET",
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "text/html" },
    });
    const cookies = (res1.headers["set-cookie"] || []).map(c => c.split(";")[0]).join("; ");
    console.log(`[PADRON-ARCA] Paso 1: HTTP ${res1.statusCode}, cookies: ${cookies.substring(0, 60)}`);

    // Paso 2: GET iframe JSP para mantener sesión y descubrir form action
    const res2 = await httpsReq({
      hostname: "seti.afip.gob.ar",
      path: "/padron-puc-constancia-internet/jsp/Constancia.jsp",
      method: "GET",
      headers: { "User-Agent": "Mozilla/5.0", "Cookie": cookies, "Accept": "text/html" },
    });
    console.log(`[PADRON-ARCA] Paso 2 (JSP): HTTP ${res2.statusCode}, largo: ${res2.body.length}`);
    // Guardar JSP para debug
    try { fs.writeFileSync(pathMod.join(BASE_DIR, "debug_jsp.html"), res2.body); } catch(e) {}

    // Extraer form action del JSP
    const formAction = res2.body.match(/action="([^"]+)"/i);
    const actionPath = formAction ? formAction[1] : "/padron-puc-constancia-internet/ConsultaConstanciaAction.do";
    console.log(`[PADRON-ARCA] Form action encontrado: ${actionPath}`);

    // Paso 3: POST el formulario
    const postData = `accion=getConstancia&cuit=${cuit}`;
    const res3 = await httpsReq({
      hostname: "seti.afip.gob.ar",
      path: actionPath.startsWith("/") ? actionPath : `/padron-puc-constancia-internet/${actionPath}`,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(postData),
        "User-Agent": "Mozilla/5.0",
        "Cookie": cookies,
        "Referer": "https://seti.afip.gob.ar/padron-puc-constancia-internet/jsp/Constancia.jsp",
      },
    }, postData);
    console.log(`[PADRON-ARCA] Paso 3 (POST): HTTP ${res3.statusCode}, largo: ${res3.body.length}`);
    try { fs.writeFileSync(pathMod.join(BASE_DIR, "debug_constancia.html"), res3.body); } catch(e) {}

    const html = res3.body;
    // Buscar razón social
    let razon_social = "";
    const patterns = [
      /Raz[oó]n\s*Social[^<]*<[^>]*>([^<]+)/i,
      /Apellido\s*y\s*Nombre[^<]*<[^>]*>([^<]+)/i,
      /denominacion[^<]*>([^<]+)/i,
      /class="[^"]*celdaDatos[^"]*"[^>]*>\s*([A-ZÁÉÍÓÚÑ][\w\s,.'-]{3,})/,
    ];
    for (const p of patterns) {
      const m = html.match(p);
      if (m && m[1].trim().length > 2) { razon_social = m[1].trim(); break; }
    }

    if (!razon_social) return { ok: false, error: `Sin datos (form=${actionPath}, ${html.length} chars)` };

    let condicion_iva = "CF";
    const ivaP = html.match(/IVA[^<]*<[^>]*>([^<]+)/i);
    if (ivaP) {
      const t = ivaP[1].toUpperCase();
      if (t.includes("INSCRIPTO")) condicion_iva = "RI";
      else if (t.includes("MONOTRIBUTO")) condicion_iva = "M";
      else if (t.includes("EXENTO")) condicion_iva = "EX";
    }
    return { ok: true, source: "arca-constancia", cuit, razon_social, condicion_iva, domicilio: "", localidad: "", provincia: "", estado_cuit: "ACTIVO" };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// Función principal: intenta múltiples fuentes
async function consultarConstanciaPublica(cuit) {
  console.log(`[PADRON] Intentando fuentes públicas para CUIT ${cuit}...`);

  // Intento 1: CuitOnline (más confiable, no requiere sesión)
  const co = await consultarCuitOnline(cuit);
  if (co.ok) return co;
  console.log(`[PADRON] CuitOnline falló: ${co.error}`);

  // Intento 2: ARCA constancia con sesión
  const arca = await consultarConstanciaARCA(cuit);
  if (arca.ok) return arca;
  console.log(`[PADRON] ARCA HTML falló: ${arca.error}`);

  return { ok: false, error: `No se pudo consultar CUIT ${cuit}. CuitOnline: ${co.error}. ARCA: ${arca.error}. Habilite ws_sr_padron_a5 para mejores resultados.` };
}

// ============================================================================
// WSFEv1 — Factura Electrónica
// ============================================================================
async function feUltimoAutorizado(token, sign, cuit, pto_vta, cbte_tipo, entorno) {
  const url = WSFE_URL[entorno] || WSFE_URL.testing;
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECompUltimoAutorizado>
      <ar:Auth>
        <ar:Token>${token}</ar:Token>
        <ar:Sign>${sign}</ar:Sign>
        <ar:Cuit>${cuit}</ar:Cuit>
      </ar:Auth>
      <ar:PtoVta>${pto_vta}</ar:PtoVta>
      <ar:CbteTipo>${cbte_tipo}</ar:CbteTipo>
    </ar:FECompUltimoAutorizado>
  </soapenv:Body>
</soapenv:Envelope>`;

  const response = await soapRequest(url, soapBody, "http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado");
  const cbteNro = response.match(/<CbteNro>(\d+)<\/CbteNro>/);
  return { cbteNro: cbteNro ? parseInt(cbteNro[1]) : 0 };
}

async function feAutorizar(token, sign, cuit, comprobante, entorno) {
  const url = WSFE_URL[entorno] || WSFE_URL.testing;

  let ivaXml = "";
  if (comprobante.iva && comprobante.iva.length > 0) {
    ivaXml = "<ar:Iva>" + comprobante.iva.map(iv => `
      <ar:AlicIva>
        <ar:Id>${iv.id}</ar:Id>
        <ar:BaseImp>${iv.base_imp}</ar:BaseImp>
        <ar:Importe>${iv.importe}</ar:Importe>
      </ar:AlicIva>`).join("") + "</ar:Iva>";
  }

  let opcionalesXml = "";
  if (comprobante.opcionales && comprobante.opcionales.length > 0) {
    opcionalesXml = "<ar:Opcionales>" + comprobante.opcionales.map(op => `
      <ar:Opcional>
        <ar:Id>${op.id}</ar:Id>
        <ar:Valor>${op.valor}</ar:Valor>
      </ar:Opcional>`).join("") + "</ar:Opcionales>";
  }

  let asocXml = "";
  if (comprobante.cbte_asoc) {
    const a = comprobante.cbte_asoc;
    asocXml = `<ar:CbtesAsoc><ar:CbteAsoc>
      <ar:Tipo>${a.tipo}</ar:Tipo>
      <ar:PtoVta>${a.pto_vta}</ar:PtoVta>
      <ar:Nro>${a.nro}</ar:Nro>
      <ar:Cuit>${a.cuit}</ar:Cuit>
      <ar:CbteFch>${a.fecha}</ar:CbteFch>
    </ar:CbteAsoc></ar:CbtesAsoc>`;
  }

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECAESolicitar>
      <ar:Auth>
        <ar:Token>${token}</ar:Token>
        <ar:Sign>${sign}</ar:Sign>
        <ar:Cuit>${cuit}</ar:Cuit>
      </ar:Auth>
      <ar:FeCAEReq>
        <ar:FeCabReq>
          <ar:CantReg>1</ar:CantReg>
          <ar:PtoVta>${comprobante.pto_vta}</ar:PtoVta>
          <ar:CbteTipo>${comprobante.cbte_tipo}</ar:CbteTipo>
        </ar:FeCabReq>
        <ar:FeDetReq>
          <ar:FECAEDetRequest>
            <ar:Concepto>${comprobante.concepto}</ar:Concepto>
            <ar:DocTipo>${comprobante.doc_tipo}</ar:DocTipo>
            <ar:DocNro>${comprobante.doc_nro}</ar:DocNro>
            <ar:CbteDesde>${comprobante.cbte_nro}</ar:CbteDesde>
            <ar:CbteHasta>${comprobante.cbte_nro}</ar:CbteHasta>
            <ar:CbteFch>${comprobante.cbte_fch}</ar:CbteFch>
            ${comprobante.concepto >= 2 && comprobante.fch_serv_desde ? `<ar:FchServDesde>${comprobante.fch_serv_desde}</ar:FchServDesde>` : ""}
            ${comprobante.concepto >= 2 && comprobante.fch_serv_hasta ? `<ar:FchServHasta>${comprobante.fch_serv_hasta}</ar:FchServHasta>` : ""}
            ${comprobante.concepto >= 2 && comprobante.fch_vto_pago ? `<ar:FchVtoPago>${comprobante.fch_vto_pago}</ar:FchVtoPago>` : ""}
            <ar:ImpTotal>${comprobante.imp_total}</ar:ImpTotal>
            <ar:ImpTotConc>${comprobante.imp_tot_conc || 0}</ar:ImpTotConc>
            <ar:ImpNeto>${comprobante.imp_neto}</ar:ImpNeto>
            <ar:ImpOpEx>${comprobante.imp_op_ex || 0}</ar:ImpOpEx>
            <ar:ImpTrib>${comprobante.imp_trib || 0}</ar:ImpTrib>
            <ar:ImpIVA>${comprobante.imp_iva}</ar:ImpIVA>
            
            <ar:MonId>${comprobante.mon_id || "PES"}</ar:MonId>
            <ar:MonCotiz>${comprobante.mon_cotiz || 1}</ar:MonCotiz>
            ${ivaXml}
            ${opcionalesXml}
            ${asocXml}
          </ar:FECAEDetRequest>
        </ar:FeDetReq>
      </ar:FeCAEReq>
    </ar:FECAESolicitar>
  </soapenv:Body>
</soapenv:Envelope>`;

  const response = await soapRequest(url, soapBody, "http://ar.gov.afip.dif.FEV1/FECAESolicitar");

  const cae = response.match(/<CAE>(\d+)<\/CAE>/);
  const caeVto = response.match(/<CAEFchVto>(\d+)<\/CAEFchVto>/);
  const resultado = response.match(/<Resultado>([^<]+)<\/Resultado>/);
  const observaciones = response.match(/<Obs>([^]*?)<\/Obs>/);
  const errores = response.match(/<Errors>([^]*?)<\/Errors>/);

  if (cae && resultado && resultado[1] === "A") {
    return { ok: true, cae: cae[1], cae_vto: caeVto ? caeVto[1] : "" };
  } else {
    return {
      ok: false,
      resultado: resultado ? resultado[1] : "Error",
      observaciones: observaciones ? observaciones[1] : "",
      errores: errores ? errores[1] : "",
      raw: response.substring(0, 2000),
    };
  }
}

// ============================================================================
// LEAF AGRICULTURE API — Integración con FieldView
// ============================================================================
const LEAF_API = "https://api.withleaf.io";

// Cache de token Leaf
let leafToken = null;
let leafTokenExpiry = null;

function leafRequest(method, path, token, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(LEAF_API + path);
    const postData = body ? JSON.stringify(body) : null;
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
    };
    if (token) options.headers["Authorization"] = `Bearer ${token}`;
    if (postData) options.headers["Content-Length"] = Buffer.byteLength(postData);

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            resolve({ _error: true, status: res.statusCode, detail: parsed });
          }
        } catch {
          resolve({ _error: true, status: res.statusCode, detail: data });
        }
      });
    });
    req.on("error", reject);
    if (postData) req.write(postData);
    req.end();
  });
}

async function leafLogin(username, password) {
  console.log(`[LEAF] Autenticando usuario: ${username}...`);
  const result = await leafRequest("POST", "/api/authenticate", null, {
    username, password, rememberMe: true
  });
  if (result._error) {
    throw new Error("Leaf login falló: " + JSON.stringify(result.detail));
  }
  leafToken = result.id_token;
  leafTokenExpiry = Date.now() + (29 * 24 * 60 * 60 * 1000); // 29 días
  console.log(`[LEAF] Token obtenido, expira en 30 días`);
  return { ok: true, token: leafToken };
}

// ============================================================================
// PROTECCIÓN CONTRA CRASHES
// ============================================================================
process.on("uncaughtException", (err) => {
  console.error("[CRASH EVITADO] Excepción no capturada:", err.message);
});
process.on("unhandledRejection", (err) => {
  console.error("[CRASH EVITADO] Promesa rechazada:", err);
});

// ============================================================================
// HTTP SERVER
// ============================================================================
const server = http.createServer(async (req, res) => {
  console.log(`[HTTP] ${req.method} ${req.url}`);

  // Timeout de 90 seg (probar varios servicios WSAA toma tiempo)
  const timeout = setTimeout(() => {
    if (!res.writableEnded && !res.headersSent) {
      console.log(`[HTTP] TIMEOUT en ${req.method} ${req.url}`);
      respond(res, 504, { ok: false, error: "Timeout: la solicitud tardó demasiado" });
    }
  }, 90000);
  res.on("finish", () => clearTimeout(timeout));

  // CORS preflight
  if (req.method === "OPTIONS") {
    respond(res, 200, { ok: true });
    return;
  }

  // ── Endpoint de prueba rápida (GET) ──
  if (req.method === "GET" && req.url === "/api/ping") {
    respond(res, 200, { ok: true, time: new Date().toISOString(), msg: "Proxy ARCA operativo" });
    return;
  }

  // ── Servidor de archivos estáticos (GET) ──
  if (req.method === "GET" && !req.url.startsWith("/api/")) {
    let filePath = req.url.split("?")[0];
    if (filePath === "/") filePath = "/erp_tango.html";
    const fullPath = pathMod.join(BASE_DIR, filePath);

    // Seguridad: no salir de BASE_DIR
    if (!fullPath.startsWith(BASE_DIR)) {
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Forbidden");
      return;
    }

    try {
      const stat = fs.statSync(fullPath);
      if (stat.isFile()) {
        const ext = pathMod.extname(fullPath).toLowerCase();
        const mime = MIME[ext] || "application/octet-stream";
        res.writeHead(200, { "Content-Type": mime });
        fs.createReadStream(fullPath).pipe(res);
        return;
      }
    } catch {}

    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
    return;
  }

  try {
    // Test endpoint
    if (req.url === "/api/test" && req.method === "POST") {
      const body = await parseBody(req);
      console.log("[TEST] Prueba de conexión recibida");
      const hasCert = !!(body.cert_pem && body.key_pem);
      respond(res, 200, { ok: true, message: "Proxy ARCA operativo", hasCert, version: "2.0-wspadron5" });
      return;
    }

    // Padrón — consulta individual
    if (req.url === "/api/padron" && req.method === "POST") {
      const body = await parseBody(req);
      const { cuit_consulta, cert_pem, key_pem, cuit, entorno } = body;

      if (!cuit_consulta) {
        respond(res, 400, { ok: false, error: "Falta cuit_consulta" });
        return;
      }

      const cuitClean = (cuit || "").replace(/-/g, "");

      // Intentar múltiples servicios WSAA del padrón
      if (cert_pem && key_pem) {
        const servicios = [
          "ws_sr_constancia_inscripcion",
          "ws_sr_padron_a5",
          "ws_sr_padron_a13",
          "ws_sr_padron_a10",
          "ws_sr_padron_a4",
        ];
        for (const servicio of servicios) {
          try {
            console.log(`[PADRON] Intentando servicio: ${servicio}...`);
            const { token, sign } = await loginCMS(cert_pem, key_pem, servicio, entorno || "testing");
            const data = await consultarPadron(cuitClean, cuit_consulta, token, sign, entorno || "testing", servicio);
            if (data.ok) {
              console.log(`[PADRON] CUIT ${cuit_consulta} (${servicio}): ${data.razon_social}`);
              data.source = servicio;
              respond(res, 200, data);
              return;
            }
            console.log(`[PADRON] ${servicio} respondió pero sin datos: ${data.error}`);
          } catch (err) {
            const msg = err.message || "";
            console.log(`[PADRON] ${servicio} falló: ${msg}`);
            // Si es error de autorización, probar siguiente servicio
            if (msg.includes("no autorizado") || msg.includes("Computador no autorizado")) continue;
            // Otro tipo de error, también probar siguiente
            continue;
          }
        }
        console.log(`[PADRON] Ningún servicio WSAA funcionó.`);
      }

      respond(res, 200, { ok: false, error: "Certificado no autorizado para consultar padrón. En ARCA con clave fiscal: busque 'Administrador de Relaciones' > Nueva relación > AFIP > Web Services > seleccione 'Consulta Padrón Alcance 5'." });
      return;
    }

    // Padrón — validación masiva
    if (req.url === "/api/padron/batch" && req.method === "POST") {
      const body = await parseBody(req);
      const { cuits, cert_pem, key_pem, cuit, entorno } = body;

      if (!cuits || !Array.isArray(cuits) || cuits.length === 0) {
        respond(res, 400, { ok: false, error: "Falta array 'cuits'" });
        return;
      }
      if (!cert_pem || !key_pem) {
        respond(res, 400, { ok: false, error: "Se requieren cert_pem y key_pem" });
        return;
      }

      const cuitClean = (cuit || "").replace(/-/g, "");
      console.log(`[PADRON-BATCH] Validando ${cuits.length} CUITs...`);

      try {
        const { token, sign } = await loginCMS(cert_pem, key_pem, "ws_sr_constancia_inscripcion", entorno || "testing");
        const results = [];

        for (const c of cuits) {
          try {
            const data = await consultarPadron(cuitClean, c, token, sign, entorno || "testing", "ws_sr_constancia_inscripcion");
            results.push(data);
            // Pausa breve para no saturar el WS
            await new Promise(r => setTimeout(r, 300));
          } catch (err) {
            results.push({ ok: false, cuit: c, error: err.message });
          }
        }

        console.log(`[PADRON-BATCH] Completado: ${results.filter(r => r.ok).length}/${cuits.length} exitosos`);
        respond(res, 200, { ok: true, results });
      } catch (err) {
        console.error(`[PADRON-BATCH] Error login:`, err.message);
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // FE — Último comprobante
    if (req.url === "/api/fe/ultimo" && req.method === "POST") {
      const body = await parseBody(req);
      const { cert_pem, key_pem, cuit, entorno, pto_vta, cbte_tipo } = body;

      if (!cert_pem || !key_pem) {
        respond(res, 400, { ok: false, error: "Se requieren cert_pem y key_pem" });
        return;
      }

      try {
        const cuitClean = (cuit || "").replace(/-/g, "");
        const { token, sign } = await loginCMS(cert_pem, key_pem, "wsfe", entorno || "testing");
        const result = await feUltimoAutorizado(token, sign, cuitClean, pto_vta, cbte_tipo, entorno || "testing");
        console.log(`[FE] Último comprobante PV=${pto_vta} Tipo=${cbte_tipo}: ${result.cbteNro}`);
        respond(res, 200, result);
      } catch (err) {
        console.error(`[FE] Error:`, err.message);
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // FE — Autorizar (solicitar CAE)
    if (req.url === "/api/fe/autorizar" && req.method === "POST") {
      const body = await parseBody(req);
      const { cert_pem, key_pem, cuit, entorno, comprobante } = body;

      if (!cert_pem || !key_pem) {
        respond(res, 400, { ok: false, error: "Se requieren cert_pem y key_pem" });
        return;
      }

      try {
        const cuitClean = (cuit || "").replace(/-/g, "");
        const { token, sign } = await loginCMS(cert_pem, key_pem, "wsfe", entorno || "testing");
        const result = await feAutorizar(token, sign, cuitClean, comprobante, entorno || "testing");
        console.log(`[FE] CAE solicitado: ${result.ok ? result.cae : "ERROR — " + (result.errores || result.observaciones)}`);
        respond(res, 200, result);
      } catch (err) {
        console.error(`[FE] Error:`, err.message);
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // ================================================================
    // LEAF AGRICULTURE ENDPOINTS
    // ================================================================

    // Leaf — Login
    if (req.url === "/api/leaf/login" && req.method === "POST") {
      const body = await parseBody(req);
      const { username, password } = body;
      if (!username || !password) {
        respond(res, 400, { ok: false, error: "Falta username o password de Leaf" });
        return;
      }
      try {
        const result = await leafLogin(username, password);
        respond(res, 200, result);
      } catch (err) {
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // Leaf — Crear usuario Leaf (grower)
    if (req.url === "/api/leaf/users" && req.method === "POST") {
      const body = await parseBody(req);
      const token = body.token || leafToken;
      if (!token) { respond(res, 401, { ok: false, error: "Sin token Leaf. Ejecute login primero." }); return; }
      try {
        const result = await leafRequest("POST", "/api/users", token, {
          name: body.name || "ERP Buffer",
          email: body.email || "",
          address: body.address || {}
        });
        if (result._error) { respond(res, result.status, { ok: false, error: result.detail }); return; }
        console.log(`[LEAF] Usuario creado: ${result.id}`);
        respond(res, 200, { ok: true, user: result });
      } catch (err) {
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // Leaf — Listar usuarios Leaf
    if (req.url === "/api/leaf/users" && req.method === "GET") {
      const token = leafToken;
      if (!token) { respond(res, 401, { ok: false, error: "Sin token Leaf" }); return; }
      try {
        const result = await leafRequest("GET", "/api/users", token);
        if (result._error) { respond(res, result.status, { ok: false, error: result.detail }); return; }
        respond(res, 200, { ok: true, users: result });
      } catch (err) {
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // Leaf — Vincular Climate FieldView
    if (req.url === "/api/leaf/cfv/connect" && req.method === "POST") {
      const body = await parseBody(req);
      const token = body.token || leafToken;
      const { leafUserId, clientId, clientSecret, apiKey } = body;
      if (!token) { respond(res, 401, { ok: false, error: "Sin token Leaf" }); return; }
      if (!leafUserId || !clientId || !clientSecret || !apiKey) {
        respond(res, 400, { ok: false, error: "Faltan datos: leafUserId, clientId, clientSecret, apiKey" });
        return;
      }
      try {
        const result = await leafRequest("POST", `/api/users/${leafUserId}/climate-field-view-credentials`, token, {
          clientId, clientSecret, apiKey
        });
        if (result._error) { respond(res, result.status, { ok: false, error: result.detail }); return; }
        console.log(`[LEAF] FieldView vinculado para usuario ${leafUserId}`);
        respond(res, 200, { ok: true, connection: result });
      } catch (err) {
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // Leaf — Obtener campos/lotes
    if (req.url.startsWith("/api/leaf/fields") && req.method === "POST") {
      const body = await parseBody(req);
      const token = body.token || leafToken;
      const { leafUserId } = body;
      if (!token) { respond(res, 401, { ok: false, error: "Sin token Leaf" }); return; }
      if (!leafUserId) { respond(res, 400, { ok: false, error: "Falta leafUserId" }); return; }
      try {
        const result = await leafRequest("GET", `/services/fields/api/users/${leafUserId}/fields`, token);
        if (result._error) { respond(res, result.status, { ok: false, error: result.detail }); return; }
        console.log(`[LEAF] Campos obtenidos: ${Array.isArray(result) ? result.length : "?"}`);
        respond(res, 200, { ok: true, fields: result });
      } catch (err) {
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // Leaf — Obtener operaciones de un campo
    if (req.url.startsWith("/api/leaf/operations") && req.method === "POST") {
      const body = await parseBody(req);
      const token = body.token || leafToken;
      const { leafUserId, fieldId, operationType } = body;
      if (!token) { respond(res, 401, { ok: false, error: "Sin token Leaf" }); return; }
      if (!leafUserId) { respond(res, 400, { ok: false, error: "Falta leafUserId" }); return; }
      try {
        let path = `/services/operations/api/users/${leafUserId}/fields/operations`;
        const params = [];
        if (fieldId) params.push(`fieldId=${fieldId}`);
        if (operationType) params.push(`operationType=${operationType}`);
        if (params.length) path += "?" + params.join("&");
        const result = await leafRequest("GET", path, token);
        if (result._error) { respond(res, result.status, { ok: false, error: result.detail }); return; }
        console.log(`[LEAF] Operaciones obtenidas: ${Array.isArray(result) ? result.length : "?"}`);
        respond(res, 200, { ok: true, operations: result });
      } catch (err) {
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // Leaf — Obtener resumen de una operación
    if (req.url.startsWith("/api/leaf/operation/") && req.method === "POST") {
      const body = await parseBody(req);
      const token = body.token || leafToken;
      const { leafUserId, operationId } = body;
      if (!token) { respond(res, 401, { ok: false, error: "Sin token Leaf" }); return; }
      if (!leafUserId || !operationId) { respond(res, 400, { ok: false, error: "Falta leafUserId u operationId" }); return; }
      try {
        const result = await leafRequest("GET", `/services/operations/api/users/${leafUserId}/fields/operations/${operationId}/summary`, token);
        if (result._error) { respond(res, result.status, { ok: false, error: result.detail }); return; }
        respond(res, 200, { ok: true, summary: result });
      } catch (err) {
        respond(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // Ruta no encontrada
    respond(res, 404, { ok: false, error: "Ruta no encontrada: " + req.url });
  } catch (err) {
    console.error("[ERROR]", err);
    respond(res, 500, { ok: false, error: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════════════════╗`);
  console.log(`║    ARCA Proxy — Buffer Química ERP                   ║`);
  console.log(`║    Puerto: ${PORT}                                      ║`);
  console.log(`║    WSpadron5 + WSFEv1 + Leaf Agriculture + Web         ║`);
  console.log(`╚══════════════════════════════════════════════════════╝\n`);
  console.log(`  ► Abrir ERP en el navegador: http://localhost:${PORT}\n`);
  console.log(`Endpoints API:`);
  console.log(`  POST /api/test             — Prueba de conexión`);
  console.log(`  POST /api/padron           — Consulta CUIT (WSpadron5)`);
  console.log(`  POST /api/padron/batch     — Validación masiva de CUITs`);
  console.log(`  POST /api/fe/ultimo        — Último comprobante (WSFEv1)`);
  console.log(`  POST /api/fe/autorizar     — Solicitar CAE (WSFEv1)`);
  console.log(`  POST /api/leaf/login       — Login Leaf Agriculture`);
  console.log(`  POST /api/leaf/fields      — Campos (Leaf/FieldView)`);
  console.log(`  POST /api/leaf/operations  — Operaciones de campo`);
  console.log(`  POST /api/leaf/cfv/connect — Vincular FieldView\n`);
});
