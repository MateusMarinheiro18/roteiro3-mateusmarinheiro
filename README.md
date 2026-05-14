Extensão validada em ambiente controlado

# Privacy Monitor (Firefox WebExtension)

Extensão Firefox para detectar ameaças de privacidade em páginas web, incluindo:

- Conexões a domínios de terceira parte (domínio + tipo de recurso)
- Uso de Web Storage (`localStorage`, `sessionStorage`) e IndexedDB
- Privacy Score com metodologia documentada
- Ameaças de hijacking (scripts suspeitos e redirecionamentos cruzados)
- Cookies (1ª vs 3ª parte, sessão vs persistente, possível supercookie)
- Fingerprinting (Canvas, WebGL e AudioContext)

## Estrutura

```
.
├── manifest.json
├── privacy_monitor.js
├── content_script.js
├── popup/
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── validacao.txt
└── README.md
```

## Como instalar no Firefox

1. Abra `about:debugging`.
2. Clique em **This Firefox**.
3. Clique em **Load Temporary Add-on...**.
4. Selecione o arquivo `manifest.json` deste projeto.

## Privacy Score (metodologia)

Pontuação inicial: **100** (quanto maior, melhor).

Débitos aplicados:

- `-8` por domínio único de terceira parte (máximo `-40`)
- `-7` por cookie persistente de terceira parte (máximo `-21`)
- `-15` por evento de fingerprinting detectado (máximo `-45`)
- `-20` por alerta de hijacking (máximo `-40`)
- `-5` se `localStorage` tiver mais de 10 chaves
- `-5` se `sessionStorage` tiver mais de 10 chaves
- `-5` se existir IndexedDB na página

Faixas de risco:

- **Baixo**: score `>= 80`
- **Médio**: score `>= 50` e `< 80`
- **Alto**: score `< 50`

## Observações

- A detecção de supercookie é heurística e sinaliza cookies com duração maior que 1 ano.
- A detecção de hijacking também é heurística e considera padrões suspeitos em scripts e redirecionamentos entre domínios diferentes.
