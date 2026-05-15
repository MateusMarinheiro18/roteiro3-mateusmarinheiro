Extensão validada em ambiente controlado

# Privacy Monitor — Extensão Firefox

Extensão WebExtension (Manifest V2) para o Firefox que detecta e exibe em tempo real os principais vetores de rastreamento e violação de privacidade presentes na navegação web.

Desenvolvida como entrega do **Roteiro 3** da disciplina de Segurança — Prof. João Eduardo — Insper 2026.

---

## Funcionalidades

| Módulo | Descrição |
|---|---|
| **Domínios de 3ª Parte** | Lista cada domínio externo contactado e o tipo de recurso (script, imagem, iframe…) |
| **Cookies** | Diferencia 1ª parte vs. 3ª parte, sessão vs. persistentes, e detecta supercookies (HSTS, ETag) |
| **Web Storage & IndexedDB** | Exibe chaves, tamanhos e domínios de localStorage, sessionStorage e IndexedDB |
| **Browser Fingerprinting** | Intercepta Canvas (`toDataURL`, `getImageData`), WebGL (`getParameter`) e AudioContext |
| **Hijacking / Hooking** | Detecta scripts externos suspeitos, injeção via `document.write`, iframes externos e redirecionamentos não autorizados |
| **Cookie Syncing** | Identifica parâmetros de sincronização de ID entre domínios em requisições de imagem/XHR |
| **Privacy Score** | Pontuação de 0–100 com grade A–F, calculada com base em todos os vetores detectados |

---

## Instalação

### Pré-requisitos
- Firefox 91 ou superior
- Git (para clonar o repositório)

### Passo a passo

1. **Clone o repositório:**
```bash
git clone <url-do-repositorio>
cd privacy-monitor
```

2. **Abra o Firefox** e acesse `about:debugging`

3. Clique em **"Este Firefox"** → **"Carregar extensão temporária…"**

4. Navegue até a pasta do projeto e selecione o arquivo **`manifest.json`**

5. A extensão será carregada e o ícone aparecerá na barra de ferramentas.

> Para uso permanente sem assinatura, habilite extensões não assinadas:  
> `about:config` → `xpinstall.signatures.required` → `false`  
> (apenas em Firefox Developer Edition ou Nightly)

---

## Como usar

1. Após instalar, navegue para qualquer site.
2. Clique no **ícone do Privacy Monitor** na barra de ferramentas.
3. O popup exibe o **Privacy Score** atual e as abas:
   - **Terceiros** — domínios externos e tipos de recurso
   - **Cookies** — contagem e classificação
   - **Storage** — dados armazenados no dispositivo
   - **Fingerprint** — APIs de fingerprinting interceptadas
   - **Hijacking** — ameaças de sequestro detectadas
   - **Score** — metodologia e penalidades aplicadas
4. Use o botão **↻ Atualizar** para recarregar os dados da aba atual.

---

## Metodologia — Privacy Score

O score inicia em **100** e é decrementado conforme os vetores detectados:

| Vetor | Fórmula | Teto |
|---|---|---|
| Domínios de 3ª parte | log₂(n+1) × 7 | −14 |
| Rastreadores conhecidos | log₂(n+1) × 8 | −16 |
| Cookies de 3ª parte | log₂(n+1) × 4 | −12 |
| Supercookies (HSTS/ETag) | log₂(n+1) × 6 | −12 |
| Canvas fingerprinting | fixo | −10 |
| WebGL fingerprinting | fixo | −10 |
| AudioContext fingerprinting | fixo | −7 |
| Script suspeito | −12 por script | −24 |
| Redirecionamento suspeito | fixo | −8 |
| iFrames externos | log₂(n+1) × 3 | −9 |
| Cookie syncing | fixo | −8 |

A fórmula **logarítmica** garante retornos decrescentes: o 1º rastreador penaliza mais que o 10º, mantendo a escala realista. Calibração: UOL ~61 (B) · DuckDuckGo ~81 (A) · Site com fingerprinting intenso ~55 (B) · Site comprometido com scripts suspeitos ~20 (D/F).

**Grades:** A ≥ 80 | B ≥ 60 | C ≥ 40 | D ≥ 20 | F < 20

---

## Estrutura do projeto

```
privacy-monitor/
├── manifest.json          # Manifest V2 — declaração da extensão
├── privacy_monitor.js     # Background script principal (webRequest, cookies, score)
├── content_script.js      # Injetado nas páginas (fingerprinting, storage, hijacking)
├── popup/
│   ├── popup.html         # Interface do usuário
│   ├── popup.js           # Lógica do popup
│   └── popup.css          # Estilos (tema escuro)
├── icons/
│   ├── icon48.png
│   └── icon96.png
├── validacao.txt          # Data de início do desenvolvimento
└── README.md              # Este arquivo
```

---

## Arquitetura técnica

### Background Script (`privacy_monitor.js`)
Utiliza a API `webRequest` (Manifest V2) para interceptar todas as requisições em tempo real, classificar domínios de 1ª e 3ª parte, analisar headers de resposta para detectar cookies e supercookies, e responder ao popup com os dados consolidados.

### Content Script (`content_script.js`)
Injetado em `document_start` para garantir execução antes do código da página. Injeta um script inline no contexto da página para fazer *monkey-patch* das APIs nativas (`Canvas`, `WebGL`, `AudioContext`) sem quebrar a sandbox do content script. Usa `MutationObserver` para detectar scripts injetados dinamicamente.

### Comunicação
- `content_script` → `background`: `browser.runtime.sendMessage`
- `popup` → `background`: `browser.runtime.sendMessage({ type: "GET_TAB_DATA" })`
- `background` → `content_script` (eventos de página): `CustomEvent` via `window.dispatchEvent`

---

## Referências

- [MDN WebExtensions](https://developer.mozilla.org/pt-BR/docs/Mozilla/Add-ons/WebExtensions/)
- [webRequest API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest)
- [Cover Your Tracks — EFF](https://coveryourtracks.eff.org)
- [Am I Unique?](https://amiunique.org)
- [Fingerprintable.org](https://fingerprintable.org)