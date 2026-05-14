/**
 * content_script.js
 * Injetado em todas as páginas em document_start.
 * Detecta: fingerprinting (Canvas, WebGL, AudioContext), Web Storage, IndexedDB,
 * e tentativas de hijacking via DOM.
 */

(function () {
    "use strict";
  
    // ─── Injetar script inline na página para interceptar APIs nativas ────────
    // O content_script roda em sandbox isolada; para patchear APIs da página,
    // precisamos injetar um <script> diretamente no DOM da página.
  
    function injectPageScript() {
      const script = document.createElement("script");
      script.textContent = `
  (function() {
    const _send = (type, api, method, detail) => {
      window.dispatchEvent(new CustomEvent('__pm_event__', {
        detail: { type, api, method, detail }
      }));
    };
  
    // ── Canvas fingerprinting ────────────────────────────────────────────────
    const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      _send('FINGERPRINTING_DETECTED', 'Canvas', 'toDataURL', 'Canvas.toDataURL chamado');
      return _toDataURL.apply(this, args);
    };
  
    const _getImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
      _send('FINGERPRINTING_DETECTED', 'Canvas', 'getImageData', 'Canvas.getImageData chamado');
      return _getImageData.apply(this, args);
    };
  
    // ── WebGL fingerprinting ─────────────────────────────────────────────────
    const _getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
      // 0x9245 = UNMASKED_VENDOR_WEBGL, 0x9246 = UNMASKED_RENDERER_WEBGL
      if (param === 0x9245 || param === 0x9246 || param === 37445 || param === 37446) {
        _send('FINGERPRINTING_DETECTED', 'WebGL', 'getParameter', 'WebGL UNMASKED_RENDERER/VENDOR lido (WEBGL_debug_renderer_info)');
      }
      return _getParameter.apply(this, arguments);
    };
  
    if (typeof WebGL2RenderingContext !== 'undefined') {
      const _getParameter2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function(param) {
        if (param === 0x9245 || param === 0x9246) {
          _send('FINGERPRINTING_DETECTED', 'WebGL', 'getParameter', 'WebGL2 UNMASKED_RENDERER/VENDOR lido');
        }
        return _getParameter2.apply(this, arguments);
      };
    }
  
    // ── AudioContext fingerprinting ──────────────────────────────────────────
    const patchAudio = (CtxClass, name) => {
      if (!CtxClass) return;
      const _createOsc = CtxClass.prototype.createOscillator;
      CtxClass.prototype.createOscillator = function(...args) {
        _send('FINGERPRINTING_DETECTED', 'AudioContext', 'createOscillator', name + '.createOscillator chamado');
        return _createOsc.apply(this, args);
      };
      const _createDyn = CtxClass.prototype.createDynamicsCompressor;
      CtxClass.prototype.createDynamicsCompressor = function(...args) {
        _send('FINGERPRINTING_DETECTED', 'AudioContext', 'createDynamicsCompressor', name + '.createDynamicsCompressor chamado');
        return _createDyn.apply(this, args);
      };
      const _createAna = CtxClass.prototype.createAnalyser;
      CtxClass.prototype.createAnalyser = function(...args) {
        _send('FINGERPRINTING_DETECTED', 'AudioContext', 'createAnalyser', name + '.createAnalyser chamado');
        return _createAna.apply(this, args);
      };
    };
    patchAudio(typeof AudioContext !== 'undefined' ? AudioContext : null, 'AudioContext');
    patchAudio(typeof OfflineAudioContext !== 'undefined' ? OfflineAudioContext : null, 'OfflineAudioContext');
  
    // ── Detecção de redirecionamentos via JS ────────────────────────────────
    const _assign = window.location.assign.bind(window.location);
    try {
      Object.defineProperty(window.location, 'assign', {
        get: function() {
          return function(url) {
            window.dispatchEvent(new CustomEvent('__pm_event__', {
              detail: { type: 'HIJACKING_DETECTED', subtype: 'redirect', data: { url, method: 'location.assign' } }
            }));
            return _assign(url);
          };
        }
      });
    } catch(e) {}
  
    const _replace = window.location.replace.bind(window.location);
    try {
      Object.defineProperty(window.location, 'replace', {
        get: function() {
          return function(url) {
            window.dispatchEvent(new CustomEvent('__pm_event__', {
              detail: { type: 'HIJACKING_DETECTED', subtype: 'redirect', data: { url, method: 'location.replace' } }
            }));
            return _replace(url);
          };
        }
      });
    } catch(e) {}
  
    // ── document.write injection detection ──────────────────────────────────
    const _docWrite = document.write.bind(document);
    document.write = function(html) {
      if (typeof html === 'string' && /<script[^>]*src=/i.test(html)) {
        window.dispatchEvent(new CustomEvent('__pm_event__', {
          detail: {
            type: 'HIJACKING_DETECTED',
            subtype: 'script_injection',
            data: { method: 'document.write', snippet: html.substring(0, 200) }
          }
        }));
      }
      return _docWrite(html);
    };
  
  })();
      `;
      (document.head || document.documentElement).appendChild(script);
      script.remove();
    }
  
    injectPageScript();
  
    // ─── Escutar eventos disparados pelo script injetado ─────────────────────
    window.addEventListener("__pm_event__", (e) => {
      const detail = e.detail;
      if (!detail || !detail.type) return;
  
      if (detail.type === "FINGERPRINTING_DETECTED") {
        browser.runtime.sendMessage({
          type: "FINGERPRINTING_DETECTED",
          api: detail.api,
          method: detail.method,
          detail: detail.detail
        }).catch(() => {});
      }
  
      if (detail.type === "HIJACKING_DETECTED") {
        browser.runtime.sendMessage({
          type: "HIJACKING_DETECTED",
          subtype: detail.subtype,
          data: detail.data
        }).catch(() => {});
      }
    });
  
    // ─── Coletar Web Storage ──────────────────────────────────────────────────
    function collectStorage() {
      const localItems = [];
      const sessionItems = [];
  
      try {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          const val = localStorage.getItem(key) || "";
          localItems.push({
            key,
            size: val.length,
            preview: val.substring(0, 80),
            domain: location.hostname
          });
        }
      } catch (e) {}
  
      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          const val = sessionStorage.getItem(key) || "";
          sessionItems.push({
            key,
            size: val.length,
            preview: val.substring(0, 80),
            domain: location.hostname
          });
        }
      } catch (e) {}
  
      return { localItems, sessionItems };
    }
  
    // ─── Coletar IndexedDB ────────────────────────────────────────────────────
    function collectIndexedDB() {
      return new Promise((resolve) => {
        const results = [];
        if (!indexedDB || !indexedDB.databases) {
          resolve(results);
          return;
        }
        indexedDB.databases().then((dbs) => {
          const promises = dbs.map((dbInfo) => {
            return new Promise((res) => {
              try {
                const req = indexedDB.open(dbInfo.name, dbInfo.version);
                req.onsuccess = (e) => {
                  const db = e.target.result;
                  const stores = Array.from(db.objectStoreNames);
                  results.push({
                    name: dbInfo.name,
                    version: dbInfo.version,
                    stores: stores,
                    domain: location.hostname
                  });
                  db.close();
                  res();
                };
                req.onerror = () => res();
              } catch {
                res();
              }
            });
          });
          Promise.all(promises).then(() => resolve(results));
        }).catch(() => resolve(results));
      });
    }
  
    // ─── Enviar dados de storage após carregamento ────────────────────────────
    function sendStorageData() {
      const { localItems, sessionItems } = collectStorage();
      collectIndexedDB().then((idbItems) => {
        browser.runtime.sendMessage({
          type: "STORAGE_DATA",
          localStorage: localItems,
          sessionStorage: sessionItems,
          indexedDB: idbItems
        }).catch(() => {});
      });
    }
  
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", sendStorageData);
    } else {
      sendStorageData();
    }
  
    // ─── Monitorar scripts adicionados dinamicamente ao DOM ──────────────────
    const scriptObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.tagName === "SCRIPT" && node.src) {
            const srcDomain = (() => {
              try { return new URL(node.src).hostname; } catch { return ""; }
            })();
            const pageDomain = location.hostname;
            if (srcDomain && srcDomain !== pageDomain) {
              const suspicious = /beef|hook\.js|xss|exploit|inject|payload|keylog|miner|coinhive|cryptoloot/i.test(node.src);
              if (suspicious) {
                browser.runtime.sendMessage({
                  type: "HIJACKING_DETECTED",
                  subtype: "script_injection",
                  data: {
                    url: node.src,
                    domain: srcDomain,
                    method: "DOM MutationObserver — script externo injetado dinamicamente",
                    reason: "Padrão suspeito detectado no src do script"
                  }
                }).catch(() => {});
              }
            }
          }
        }
      }
    });
  
    scriptObserver.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  
  })();