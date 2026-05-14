/**
 * privacy_monitor.js
 * Script principal (background) da extensão Privacy Monitor.
 * Responsável por interceptar requisições de rede, analisar cookies,
 * detectar hijacking e calcular o Privacy Score.
 */

// ─── Estado global por aba ────────────────────────────────────────────────────
const tabData = {};

function initTab(tabId) {
  tabData[tabId] = {
    firstPartyDomain: null,
    thirdPartyDomains: {},   // { domain: { count, types: Set } }
    cookies: {
      firstParty: [],
      thirdParty: [],
      session: [],
      persistent: [],
      supercookies: []
    },
    hijacking: {
      suspiciousScripts: [],
      redirectAttempts: [],
      externalIframes: []
    },
    fingerprinting: [],      // recebido via message do content_script
    storage: {               // recebido via message do content_script
      localStorage: [],
      sessionStorage: [],
      indexedDB: []
    },
    privacyScore: 100,
    scoreBreakdown: []
  };
}

// ─── Extração de domínio raiz ─────────────────────────────────────────────────
function getRootDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.replace(/^www\./, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  // Trata casos como .co.uk, .com.br
  const sldMap = ["co", "com", "net", "org", "edu", "gov"];
  if (parts.length >= 3 && sldMap.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function extractDomain(url) {
  try {
    return getRootDomain(new URL(url).hostname);
  } catch {
    return "";
  }
}

// ─── Domínios conhecidos de rastreamento / CDN suspeitos ──────────────────────
const KNOWN_TRACKERS = [
  "doubleclick.net", "googlesyndication.com", "google-analytics.com",
  "googletagmanager.com", "facebook.net", "facebook.com", "fbcdn.net",
  "twitter.com", "analytics.twitter.com", "linkedin.com", "ads.linkedin.com",
  "scorecardresearch.com", "quantserve.com", "outbrain.com", "taboola.com",
  "adsrvr.org", "rubiconproject.com", "openx.net", "pubmatic.com",
  "advertising.com", "criteo.com", "amazon-adsystem.com", "hotjar.com",
  "mixpanel.com", "segment.com", "amplitude.com", "heap.io",
  "mouseflow.com", "fullstory.com", "logrocket.com", "clarity.ms",
  "pardot.com", "marketo.net", "hubspot.com", "intercom.io"
];

function isKnownTracker(domain) {
  return KNOWN_TRACKERS.some(t => domain === t || domain.endsWith("." + t));
}

// ─── Scripts suspeitos (padrões de hijacking/hooking) ────────────────────────
const SUSPICIOUS_PATTERNS = [
  /beef/i, /xss/i, /hook\.js/i, /exploit/i, /payload/i,
  /keylog/i, /stealer/i, /phish/i, /inject/i, /backdoor/i,
  /c2\./i, /command.*control/i, /rat\./i, /cryptojack/i, /miner\.js/i,
  /coinhive/i, /cryptoloot/i, /webmr\.js/i
];

function isSuspiciousScript(url) {
  return SUSPICIOUS_PATTERNS.some(p => p.test(url));
}

// ─── Listener principal de requisições ───────────────────────────────────────
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type, originUrl } = details;
    if (tabId < 0) return;
    if (!tabData[tabId]) initTab(tabId);

    const data = tabData[tabId];
    const reqDomain = extractDomain(url);
    const originDomain = originUrl ? extractDomain(originUrl) : data.firstPartyDomain;

    // Define o domínio de 1ª parte pela primeira requisição do documento
    if (type === "main_frame") {
      data.firstPartyDomain = reqDomain;
      return;
    }

    if (!data.firstPartyDomain || !reqDomain) return;

    const isThirdParty = reqDomain !== data.firstPartyDomain;

    if (isThirdParty) {
      // Registra domínio de terceira parte
      if (!data.thirdPartyDomains[reqDomain]) {
        data.thirdPartyDomains[reqDomain] = {
          count: 0,
          types: [],
          isTracker: isKnownTracker(reqDomain),
          urls: []
        };
      }
      const entry = data.thirdPartyDomains[reqDomain];
      entry.count++;
      if (!entry.types.includes(type)) entry.types.push(type);
      if (entry.urls.length < 5) entry.urls.push(url);
    }

    // Detecção de scripts suspeitos (hijacking/hooking)
    if (type === "script") {
      if (isSuspiciousScript(url)) {
        data.hijacking.suspiciousScripts.push({
          url,
          domain: reqDomain,
          isThirdParty,
          reason: "Padrão suspeito no nome/URL do script"
        });
      }
    }

    // iframes externos — potencial clickjacking
    if (type === "sub_frame" && isThirdParty) {
      data.hijacking.externalIframes.push({
        url,
        domain: reqDomain
      });
    }
  },
  { urls: ["<all_urls>"] }
);

// ─── Listener de headers de resposta (cookies + supercookies) ─────────────────
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const { tabId, url, responseHeaders, type } = details;
    if (tabId < 0 || !tabData[tabId]) return;

    const data = tabData[tabId];
    const reqDomain = extractDomain(url);
    const isThirdParty = reqDomain !== data.firstPartyDomain;

    for (const header of responseHeaders) {
      const name = header.name.toLowerCase();
      const value = header.value || "";

      // ── Set-Cookie ─────────────────────────────────────────────────────────
      if (name === "set-cookie") {
        const cookies = value.split("\n").filter(Boolean);
        for (const cookieStr of cookies) {
          const parts = cookieStr.split(";").map(s => s.trim());
          const nameVal = parts[0] || "";
          const cookieName = nameVal.split("=")[0].trim();
          const maxAge = parts.find(p => p.toLowerCase().startsWith("max-age="));
          const expires = parts.find(p => p.toLowerCase().startsWith("expires="));
          const isSession = !maxAge && !expires;
          const isSecure = parts.some(p => p.toLowerCase() === "secure");
          const httpOnly = parts.some(p => p.toLowerCase() === "httponly");
          const sameSite = parts.find(p => p.toLowerCase().startsWith("samesite=")) || "none";

          const cookieObj = {
            name: cookieName,
            domain: reqDomain,
            isThirdParty,
            isSession,
            isPersistent: !isSession,
            isSecure,
            httpOnly,
            sameSite,
            raw: cookieStr.substring(0, 120)
          };

          if (isThirdParty) data.cookies.thirdParty.push(cookieObj);
          else data.cookies.firstParty.push(cookieObj);

          if (isSession) data.cookies.session.push(cookieObj);
          else data.cookies.persistent.push(cookieObj);
        }
      }

      // ── HSTS Supercookies ──────────────────────────────────────────────────
      if (name === "strict-transport-security") {
        if (value.includes("includeSubDomains") && isThirdParty) {
          data.cookies.supercookies.push({
            type: "HSTS Supercookie",
            domain: reqDomain,
            value: value.substring(0, 100),
            risk: "Alto — pode ser usado para rastreamento via HSTS includeSubDomains"
          });
        }
      }

      // ── ETag Supercookie (heurística) ──────────────────────────────────────
      if (name === "etag" && isThirdParty && type === "image") {
        const etagVal = value.replace(/"/g, "");
        if (etagVal.length > 16) {
          data.cookies.supercookies.push({
            type: "ETag Supercookie",
            domain: reqDomain,
            value: etagVal.substring(0, 40),
            risk: "Médio — ETag de recurso de imagem de terceiro pode ser reutilizado para identificação"
          });
        }
      }
    }

    // ── Detecção de redirecionamento suspeito ──────────────────────────────
    const status = details.statusCode;
    if ([301, 302, 303, 307, 308].includes(status) && isThirdParty) {
      const location = responseHeaders.find(h => h.name.toLowerCase() === "location");
      if (location) {
        data.hijacking.redirectAttempts.push({
          from: url,
          to: location.value,
          statusCode: status,
          domain: reqDomain
        });
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ─── Cookie Syncing ───────────────────────────────────────────────────────────
// Detecta parâmetros de URL que parecem IDs de usuário passados entre domínios
const SYNC_PARAMS = [
  "uid", "uuid", "user_id", "userid", "visitor_id", "visitorid",
  "cid", "client_id", "pid", "partner_id", "gdpr_consent",
  "id", "aid", "sid", "gid", "lid"
];

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type } = details;
    if (tabId < 0 || !tabData[tabId]) return;
    if (type !== "image" && type !== "xmlhttprequest" && type !== "other") return;

    const data = tabData[tabId];
    try {
      const u = new URL(url);
      const reqDomain = getRootDomain(u.hostname);
      if (reqDomain === data.firstPartyDomain) return;

      const foundParams = [];
      for (const param of SYNC_PARAMS) {
        if (u.searchParams.has(param)) {
          const val = u.searchParams.get(param);
          if (val && val.length > 4) foundParams.push(`${param}=${val.substring(0, 20)}`);
        }
      }

      if (foundParams.length >= 2) {
        if (!data.cookieSyncing) data.cookieSyncing = [];
        data.cookieSyncing.push({
          url: url.substring(0, 150),
          domain: reqDomain,
          params: foundParams,
          type
        });
      }
    } catch {}
  },
  { urls: ["<all_urls>"] }
);

// ─── Receber mensagens do content_script ──────────────────────────────────────
browser.runtime.onMessage.addListener((message, sender) => {
  const tabId = sender.tab ? sender.tab.id : null;
  if (!tabId || tabId < 0) return;
  if (!tabData[tabId]) initTab(tabId);

  const data = tabData[tabId];

  if (message.type === "FINGERPRINTING_DETECTED") {
    const existing = data.fingerprinting.find(f => f.api === message.api && f.method === message.method);
    if (!existing) {
      data.fingerprinting.push({
        api: message.api,
        method: message.method,
        detail: message.detail,
        timestamp: Date.now()
      });
    }
  }

  if (message.type === "STORAGE_DATA") {
    data.storage.localStorage = message.localStorage || [];
    data.storage.sessionStorage = message.sessionStorage || [];
    data.storage.indexedDB = message.indexedDB || [];
  }

  if (message.type === "HIJACKING_DETECTED") {
    if (message.subtype === "script_injection") {
      data.hijacking.suspiciousScripts.push(message.data);
    }
    if (message.subtype === "redirect") {
      data.hijacking.redirectAttempts.push(message.data);
    }
  }
});

// ─── Calcular Privacy Score ───────────────────────────────────────────────────
function calculatePrivacyScore(data) {
  let score = 100;
  const breakdown = [];

  // Terceiros
  const thirdPartyCount = Object.keys(data.thirdPartyDomains).length;
  const trackerCount = Object.values(data.thirdPartyDomains).filter(d => d.isTracker).length;

  if (thirdPartyCount > 0) {
    const penalty = Math.min(thirdPartyCount * 2, 20);
    score -= penalty;
    breakdown.push({ label: `${thirdPartyCount} domínios de terceira parte`, penalty: -penalty, category: "third_party" });
  }
  if (trackerCount > 0) {
    const penalty = Math.min(trackerCount * 5, 20);
    score -= penalty;
    breakdown.push({ label: `${trackerCount} rastreadores conhecidos`, penalty: -penalty, category: "tracker" });
  }

  // Cookies de terceiros
  if (data.cookies.thirdParty.length > 0) {
    const penalty = Math.min(data.cookies.thirdParty.length * 3, 15);
    score -= penalty;
    breakdown.push({ label: `${data.cookies.thirdParty.length} cookies de terceira parte`, penalty: -penalty, category: "cookie" });
  }
  if (data.cookies.supercookies.length > 0) {
    const penalty = data.cookies.supercookies.length * 8;
    score -= penalty;
    breakdown.push({ label: `${data.cookies.supercookies.length} supercookies detectados`, penalty: -penalty, category: "supercookie" });
  }

  // Fingerprinting
  const fpTypes = new Set(data.fingerprinting.map(f => f.api));
  if (fpTypes.has("Canvas")) { score -= 15; breakdown.push({ label: "Canvas fingerprinting detectado", penalty: -15, category: "fingerprint" }); }
  if (fpTypes.has("WebGL")) { score -= 15; breakdown.push({ label: "WebGL fingerprinting detectado", penalty: -15, category: "fingerprint" }); }
  if (fpTypes.has("AudioContext")) { score -= 10; breakdown.push({ label: "AudioContext fingerprinting detectado", penalty: -10, category: "fingerprint" }); }

  // Hijacking
  if (data.hijacking.suspiciousScripts.length > 0) {
    const penalty = data.hijacking.suspiciousScripts.length * 10;
    score -= penalty;
    breakdown.push({ label: `${data.hijacking.suspiciousScripts.length} script(s) suspeito(s)`, penalty: -penalty, category: "hijack" });
  }
  if (data.hijacking.redirectAttempts.length > 0) {
    score -= 10;
    breakdown.push({ label: `${data.hijacking.redirectAttempts.length} redirecionamento(s) suspeito(s)`, penalty: -10, category: "hijack" });
  }
  if (data.hijacking.externalIframes.length > 0) {
    const penalty = Math.min(data.hijacking.externalIframes.length * 5, 15);
    score -= penalty;
    breakdown.push({ label: `${data.hijacking.externalIframes.length} iframe(s) externo(s)`, penalty: -penalty, category: "hijack" });
  }

  // Cookie syncing
  if (data.cookieSyncing && data.cookieSyncing.length > 0) {
    score -= 10;
    breakdown.push({ label: `${data.cookieSyncing.length} possível(is) cookie syncing`, penalty: -10, category: "sync" });
  }

  score = Math.max(0, score);

  let grade, color;
  if (score >= 80) { grade = "A"; color = "#22c55e"; }
  else if (score >= 60) { grade = "B"; color = "#84cc16"; }
  else if (score >= 40) { grade = "C"; color = "#eab308"; }
  else if (score >= 20) { grade = "D"; color = "#f97316"; }
  else { grade = "F"; color = "#ef4444"; }

  return { score, grade, color, breakdown };
}

// ─── Responder ao popup ───────────────────────────────────────────────────────
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_TAB_DATA") {
    const tabId = message.tabId;
    if (!tabData[tabId]) {
      sendResponse({ error: "Nenhum dado para esta aba." });
      return true;
    }
    const data = tabData[tabId];
    const privacyResult = calculatePrivacyScore(data);
    sendResponse({
      firstPartyDomain: data.firstPartyDomain,
      thirdPartyDomains: data.thirdPartyDomains,
      cookies: data.cookies,
      hijacking: data.hijacking,
      fingerprinting: data.fingerprinting,
      storage: data.storage,
      cookieSyncing: data.cookieSyncing || [],
      privacyScore: privacyResult
    });
    return true;
  }
});

// ─── Limpar dados ao navegar para nova página ─────────────────────────────────
browser.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    initTab(details.tabId);
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
});