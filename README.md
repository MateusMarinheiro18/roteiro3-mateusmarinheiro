# Extensão validada em ambiente controlado

## Descrição do Projeto

Esta extensão para o Firefox foi desenvolvida para detectar ameaças à privacidade dos usuários na web. Ela utiliza diversas técnicas para monitorar e avaliar a segurança das conexões e do armazenamento de dados em páginas da web.

## Estrutura do Projeto

O projeto é composto pelos seguintes arquivos:

- **manifest.json**: O manifesto da extensão, que especifica as permissões, scripts e configurações necessárias para o funcionamento da extensão no Firefox.
- **privacy_monitor.js**: O script principal que utiliza a API `webRequest` para interceptar requisições, classificar domínios como de 1ª ou 3ª parte, registrar tipos de recursos e interceptar cookies.
- **content_script.js**: Um script injetado nas páginas da web para detectar fingerprinting e acessar Web Storage (localStorage, sessionStorage) e IndexedDB. Ele faz monkey-patching das APIs suspeitas para detectar tentativas de fingerprinting.
- **popup/**: Uma pasta que contém os arquivos da interface do usuário da extensão.
  - **popup.html**: A interface do usuário onde os dados sobre ameaças à privacidade serão exibidos.
  - **popup.js**: O script que gerencia a lógica da interface do usuário, lidando com eventos e atualizando a interface com as informações coletadas pelo background script.
  - **popup.css**: Os estilos para a interface do usuário, garantindo que a apresentação seja clara e atraente.
- **validacao.txt**: Um arquivo que contém a data de início do desenvolvimento da extensão.

## Instruções de Uso

1. **Instalação**: Para instalar a extensão, acesse a página de extensões do Firefox e carregue o diretório `privacy-monitor` como uma extensão temporária.
2. **Uso**: Após a instalação, a extensão começará a monitorar as conexões e o armazenamento de dados automaticamente. A interface do usuário pode ser acessada clicando no ícone da extensão na barra de ferramentas do Firefox.
3. **Relatórios**: A extensão exibirá informações sobre conexões de terceiros, armazenamento de dados, cookies e tentativas de fingerprinting.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests no repositório do projeto.