const tabFindings = Object.create(null);
const SUSPICIOUS_SCRIPT_KEYWORDS = [
  "inject",
  "hijack",
  "redirect",
  "malware",
  "phish",
  "beacon",
  "tracker",
  "fingerprint",
  "cryptominer"
];

function safeUrl(rawUrl) {
  try {
    return new URL(rawUrl);
  } catch (_error) {
    return null;
  }
}

function getHostname(rawUrl) {
  const parsed = safeUrl(rawUrl);
  return parsed ? parsed.hostname.toLowerCase() : "";
}

function getBaseDomain(hostname) {
  if (!hostname) {
    return "";
  }
  const clean = hostname.replace(/^\.+/, "").toLowerCase();
  const parts = clean.split(".").filter(Boolean);
  if (parts.length <= 2) {
    return clean;
  }
  return parts.slice(-2).join(".");
}

function isSameParty(domainA, domainB) {
  if (!domainA || !domainB) {
    return true;
  }
  return getBaseDomain(domainA) === getBaseDomain(domainB);
}

function ensureTab(tabId, pageUrl) {
  if (!tabFindings[tabId]) {
    tabFindings[tabId] = {
      pageUrl: pageUrl || "",
      pageDomain: getHostname(pageUrl),
      thirdPartyConnections: [],
      cookies: [],
      storage: {
        localStorage: { count: 0, keys: [] },
        sessionStorage: { count: 0, keys: [] },
        indexedDB: { count: 0, names: [] }
      },
      fingerprinting: [],
      hijacking: [],
      redirects: []
    };
  }

  const tabData = tabFindings[tabId];
  if (pageUrl) {
    tabData.pageUrl = pageUrl;
    tabData.pageDomain = getHostname(pageUrl);
  }
  return tabData;
}

function pushUnique(list, item, signature) {
  const key = signature || JSON.stringify(item);
  const exists = list.some((entry) => JSON.stringify(entry) === key || entry.__signature === key);
  if (!exists) {
    const next = { ...item, __signature: key };
    list.push(next);
  }
}

function parseSetCookie(headerValue) {
  const parts = headerValue.split(";").map((part) => part.trim());
  const [nameValue, ...attributeParts] = parts;
  const eqIndex = nameValue.indexOf("=");
  const name = eqIndex >= 0 ? nameValue.slice(0, eqIndex).trim() : nameValue.trim();
  const value = eqIndex >= 0 ? nameValue.slice(eqIndex + 1).trim() : "";

  const attributes = {};
  attributeParts.forEach((part) => {
    const attrIndex = part.indexOf("=");
    if (attrIndex === -1) {
      attributes[part.toLowerCase()] = true;
    } else {
      const attrName = part.slice(0, attrIndex).trim().toLowerCase();
      const attrValue = part.slice(attrIndex + 1).trim();
      attributes[attrName] = attrValue;
    }
  });

  return {
    name,
    value,
    attributes
  };
}

function isSuspiciousScript(url) {
  const lower = (url || "").toLowerCase();
  return SUSPICIOUS_SCRIPT_KEYWORDS.some((keyword) => lower.includes(keyword));
}

function cleanEntry(entry) {
  const { __signature, ...cleaned } = entry;
  return cleaned;
}

function computeScore(tabData) {
  let score = 100;

  const thirdPartyDomains = new Set(tabData.thirdPartyConnections.map((conn) => conn.domain));
  score -= Math.min(40, thirdPartyDomains.size * 8);

  const persistentThirdPartyCookies = tabData.cookies.filter((cookie) => cookie.isThirdParty && cookie.persistence === "persistente");
  score -= Math.min(21, persistentThirdPartyCookies.length * 7);

  score -= Math.min(45, tabData.fingerprinting.length * 15);
  score -= Math.min(40, tabData.hijacking.length * 20);

  if (tabData.storage.localStorage.count > 10) {
    score -= 5;
  }
  if (tabData.storage.sessionStorage.count > 10) {
    score -= 5;
  }
  if (tabData.storage.indexedDB.count > 0) {
    score -= 5;
  }

  return Math.max(0, score);
}

function getRiskLevel(score) {
  if (score >= 80) return "Baixo";
  if (score >= 50) return "Médio";
  return "Alto";
}

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabFindings[tabId];
});

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) {
      return;
    }

    const tabData = ensureTab(details.tabId, details.type === "main_frame" ? details.url : "");

    const pageDomain = tabData.pageDomain || getHostname(details.documentUrl || details.initiator || "");
    const requestDomain = getHostname(details.url);

    if (!isSameParty(pageDomain, requestDomain) && requestDomain) {
      pushUnique(
        tabData.thirdPartyConnections,
        {
          domain: requestDomain,
          resourceType: details.type,
          url: details.url
        },
        `${requestDomain}|${details.type}|${details.url}`
      );
    }

    if (details.type === "script" && isSuspiciousScript(details.url)) {
      pushUnique(
        tabData.hijacking,
        {
          type: "script_suspeito",
          description: "Script com padrão suspeito no URL.",
          url: details.url
        },
        `script|${details.url}`
      );
    }
  },
  { urls: ["<all_urls>"] }
);

browser.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.tabId < 0) {
      return;
    }

    const tabData = ensureTab(details.tabId);
    const fromDomain = getHostname(details.url);
    const toDomain = getHostname(details.redirectUrl);

    if (fromDomain && toDomain && fromDomain !== toDomain) {
      pushUnique(
        tabData.redirects,
        {
          from: details.url,
          to: details.redirectUrl
        },
        `${details.url}|${details.redirectUrl}`
      );

      if (!isSameParty(fromDomain, toDomain)) {
        pushUnique(
          tabData.hijacking,
          {
            type: "redirecionamento_cruzado",
            description: "Redirecionamento entre domínios distintos detectado.",
            from: details.url,
            to: details.redirectUrl
          },
          `redirect|${details.url}|${details.redirectUrl}`
        );
      }
    }
  },
  { urls: ["<all_urls>"] }
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0 || !Array.isArray(details.responseHeaders)) {
      return;
    }

    const tabData = ensureTab(details.tabId);
    const requestDomain = getHostname(details.url);
    const pageDomain = tabData.pageDomain || getHostname(details.documentUrl || details.initiator || details.url);

    details.responseHeaders.forEach((header) => {
      if (!header || !header.name || header.name.toLowerCase() !== "set-cookie" || !header.value) {
        return;
      }

      const parsed = parseSetCookie(header.value);
      const cookieDomain = (parsed.attributes.domain || requestDomain || "").replace(/^\./, "").toLowerCase();
      const hasMaxAge = parsed.attributes["max-age"] !== undefined;
      const hasExpires = parsed.attributes.expires !== undefined;
      const persistence = hasMaxAge || hasExpires ? "persistente" : "sessao";

      let supercookie = false;
      if (hasMaxAge) {
        const maxAge = Number(parsed.attributes["max-age"]);
        if (Number.isFinite(maxAge) && maxAge > 31536000) {
          supercookie = true;
        }
      }
      if (hasExpires) {
        const expiresAt = Date.parse(parsed.attributes.expires);
        if (Number.isFinite(expiresAt) && expiresAt - Date.now() > 31536000000) {
          supercookie = true;
        }
      }

      pushUnique(
        tabData.cookies,
        {
          name: parsed.name,
          domain: cookieDomain,
          party: isSameParty(cookieDomain, pageDomain) ? "primeira" : "terceira",
          isThirdParty: !isSameParty(cookieDomain, pageDomain),
          persistence,
          supercookie,
          sameSite: parsed.attributes.samesite || "não informado",
          secure: Boolean(parsed.attributes.secure),
          httpOnly: Boolean(parsed.attributes.httponly)
        },
        `cookie|${parsed.name}|${cookieDomain}|${persistence}|${parsed.attributes.samesite || ""}|${parsed.attributes.secure ? 1 : 0}|${parsed.attributes.httponly ? 1 : 0}`
      );
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || !message.type) {
    return undefined;
  }

  const tabId = sender && sender.tab ? sender.tab.id : message.tabId;
  if (typeof tabId !== "number") {
    return undefined;
  }

  const tabData = ensureTab(tabId, message.pageUrl || (sender.tab ? sender.tab.url : ""));

  if (message.type === "privacy-event" && message.event === "fingerprinting") {
    pushUnique(
      tabData.fingerprinting,
      {
        api: message.api,
        url: message.url || tabData.pageUrl,
        timestamp: message.timestamp || Date.now()
      },
      `fp|${message.api}|${message.url || ""}|${message.timestamp || ""}`
    );
    return Promise.resolve({ ok: true });
  }

  if (message.type === "storage-report") {
    tabData.storage = {
      localStorage: message.localStorage || { count: 0, keys: [] },
      sessionStorage: message.sessionStorage || { count: 0, keys: [] },
      indexedDB: message.indexedDB || { count: 0, names: [] }
    };
    return Promise.resolve({ ok: true });
  }

  if (message.type === "get-tab-data") {
    const snapshot = {
      pageUrl: tabData.pageUrl,
      pageDomain: tabData.pageDomain,
      thirdPartyConnections: tabData.thirdPartyConnections.map(cleanEntry),
      cookies: tabData.cookies.map(cleanEntry),
      storage: tabData.storage,
      fingerprinting: tabData.fingerprinting.map(cleanEntry),
      hijacking: tabData.hijacking.map(cleanEntry),
      redirects: tabData.redirects.map(cleanEntry)
    };
    const score = computeScore(snapshot);

    return Promise.resolve({
      ...snapshot,
      privacyScore: {
        score,
        riskLevel: getRiskLevel(score)
      }
    });
  }

  return undefined;
});
