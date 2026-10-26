/* ================================================================
   FIXER OS — fixeros-auth.js (v1.3)
   Camada de autenticação partilhada, para incluir no <head> ou
   antes do </body> de qualquer um dos 3 index.html (Fiscal,
   ReconBank, DocScan).

   USO em cada módulo:
   1. Incluir este ficheiro: <script src="fixeros-auth.js"></script>
   2. No topo do <script> principal de cada app, chamar:
        FixerAuth.exigirLogin('fiscal')      // ou 'reconbank' / 'docscan'
          .then(utilizador => { inicializa a app normalmente })
          .catch(() => { já foi redireccionado para o login, nada a fazer aqui });
   3. Sempre que o módulo envia um POST ao seu próprio GAS, incluir
      o token no payload: { ...payload, authToken: FixerAuth.getToken() }
      — cada Code.gs dos 3 módulos deve validar esse token (ver
      snippet de middleware em fixeros-auth-middleware.gs.txt)

   v1.3 — SESSÃO EXPIRADA SEM PERDER O TRABALHO: o token dura 12 h
   (TOKEN_VALIDADE_H no Auth). Antes, um pedido feito com o token
   vencido devolvia "Token expirado" e o contabilista tinha de
   recarregar a página e refazer tudo. Agora este ficheiro vigia os
   pedidos que levam o token: se a sessão venceu (antes de enviar ou
   na resposta do servidor), abre um login POR CIMA do ecrã (os
   ficheiros e resultados ficam onde estão) e, depois de entrar,
   repete o mesmo pedido com o token novo. Nenhum módulo precisa de
   mudar código.

   v1.2 — ecrã de login com o tema Fixer OS (claro/escuro, cor por módulo) e clienteId no SSO.

   v1.1 — CORRECÇÃO: exigirLogin() agora lê e valida o
   "?fixerosToken=" que o hub (Fixer OS Essencial) coloca na URL ao
   abrir um módulo. Antes desta versão, esse parâmetro era gerado
   pelo hub mas nunca lido aqui — o handoff de sessão não tinha
   nenhum efeito prático, a pessoa caía sempre no login manual.

   RECOMENDADO (fora deste ficheiro, no <head> de cada index.html):
     <meta name="referrer" content="no-referrer">
   Isto evita que o token, enquanto ainda visível na URL no instante
   inicial do carregamento, vaze via cabeçalho Referer para recursos
   externos (Google Fonts, CDN de ícones) que a página carrega. Este
   ficheiro tenta injectar a mesma meta tag por defeito, o mais cedo
   possível — mas a tag no HTML é a protecção garantida, porque corre
   antes de qualquer pedido externo dessa página começar.
   ================================================================ */
(function injectarReferrerPolicy() {
  if (document.querySelector('meta[name="referrer"]')) return;
  var meta = document.createElement('meta');
  meta.name = 'referrer';
  meta.content = 'no-referrer';
  document.head ? document.head.prepend(meta) : document.documentElement.prepend(meta);
})();

const FixerAuth = (function () {
  const AUTH_GAS_URL = 'https://script.google.com/macros/s/AKfycbxutHxDOeP4sYDyYLRk5psXl8ZXfWm-_sO09w_CZClBhwCvel7qHR04TbLOXpJFdT9wDA/exec'; // /exec do Auth.gs
  const TOKEN_KEY = 'fixeros_auth_token';
  const USER_KEY  = 'fixeros_auth_user';

  function getToken() { return localStorage.getItem(TOKEN_KEY) || ''; }
  function getUser()  { try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch(e) { return null; } }
  function limparSessao() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); }

  // fetch original do browser: os pedidos do próprio login nunca passam pela vigilância da sessão (v1.3)
  const fetchOriginal = window.fetch.bind(window);

  async function login(email, password) {
    const resp = await fetchOriginal(AUTH_GAS_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify({ accao: 'login', email, password })
    });
    const data = await resp.json();
    if (!data.ok) throw new Error(data.erro || 'Login falhou');
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(data.utilizador));
    return data.utilizador;
  }

  function logout() {
    limparSessao();
    renderGate(document.body.dataset.fixerosModulo || '');
  }

  // Valida localmente (expiração) sem chamar rede — validação forte
  // (assinatura) continua a acontecer no backend de cada módulo a
  // cada pedido; isto aqui é só para decidir se mostra o gate já.
  function pareceValido() {
    const token = getToken();
    if (!token || token.indexOf('.') === -1) return false;
    try {
      const payloadB64 = token.split('.')[0];
      const payload = atob(payloadB64.replace(/-/g,'+').replace(/_/g,'/'));
      const campos = payload.split('|');
      const expiraEm = Number(campos[4]);
      return Date.now() < expiraEm;
    } catch (e) { return false; }
  }

  function utilizadorTemAcesso(modulo) {
    const u = getUser();
    return !!(u && Array.isArray(u.modulos) && u.modulos.indexOf(modulo) !== -1);
  }

  // ================================================================
  // CONSUMIR TOKEN DA URL (handoff de SSO vindo do hub)
  //
  // O hub (Fixer OS Essencial) abre cada módulo com
  // "?fixerosToken=...". Antes desta função, nada neste ficheiro lia
  // esse parâmetro — o handoff de sessão nunca funcionava de facto,
  // a pessoa caía sempre no login manual mesmo vindo já autenticada
  // do hub. Esta função fecha esse gap:
  //
  //   1. Lê fixerosToken da query string, se presente.
  //   2. NÃO confia nele às cegas — valida contra o Auth.gs central
  //      (mesma validação de assinatura HMAC que os backends de
  //      módulo já fazem, nunca uma decisão local não verificada).
  //   3. Se válido E autorizado para este módulo, grava sessão local
  //      exactamente como faria um login manual bem-sucedido.
  //   4. Remove o token da URL (history.replaceState) assim que
  //      consumido — reduz a janela em que fica visível na barra de
  //      endereço, no histórico do browser, ou copiável/partilhável
  //      por engano.
  //
  // Retorna uma Promise<boolean> — true se uma sessão válida ficou
  // gravada a partir da URL, false caso contrário (sem token na URL,
  // token inválido/expirado, ou utilizador sem acesso a este módulo).
  // ================================================================
  async function consumirTokenDaURL(modulo) {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenDaUrl = urlParams.get('fixerosToken');
    if (!tokenDaUrl) return false;

    // Tira o token da URL imediatamente, independentemente do resultado
    // da validação — não faz sentido deixá-lo visível depois de lido.
    urlParams.delete('fixerosToken');
    const urlLimpa = window.location.pathname +
      (urlParams.toString() ? '?' + urlParams.toString() : '') +
      window.location.hash;
    window.history.replaceState({}, document.title, urlLimpa);

    try {
      const resp = await fetchOriginal(AUTH_GAS_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ accao: 'validarToken', token: tokenDaUrl, modulo: modulo })
      });
      const data = await resp.json();
      if (!data.ok) {
        // Token inválido/expirado/sem acesso — não grava nada, cai no
        // fluxo normal de login manual. Não é um erro fatal do módulo.
        return false;
      }

      localStorage.setItem(TOKEN_KEY, tokenDaUrl);
      localStorage.setItem(USER_KEY, JSON.stringify({
        email: data.email, empresa: data.empresa, clienteId: data.clienteId, role: data.role, modulos: data.modulos
      }));
      return true;
    } catch (e) {
      // Falha de rede a validar — mais seguro tratar como handoff
      // falhado do que confiar num token nunca verificado.
      return false;
    }
  }

  // Cores: a do módulo vem de <body data-fixeros-cor="#hex">; o tema segue a
  // preferência partilhada 'fixeros_tema' (claro, escuro ou automático).
  function coresTema() {
    var pref = 'auto';
    try { pref = localStorage.getItem('fixeros_tema') || 'auto'; } catch (e) {}
    var escuro = pref === 'dark' || (pref === 'auto' && window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches);
    var c = escuro
      ? { bg: '#0E1210', card: '#171D1A', borda: '#2A3530', texto: '#E8F0EC', suave: '#9DB0A6', campo: '#0E1210' }
      : { bg: '#F4F6F3', card: '#FFFFFF', borda: '#DDE3DC', texto: '#15201E', suave: '#5C6B64', campo: '#FFFFFF' };
    c.cor = (document.body && document.body.dataset.fixerosCor) || '#0E6B54';
    return c;
  }

  // ================================================================
  // v1.3 — RENOVAR A SESSÃO SEM PERDER O TRABALHO
  //
  // Os pedidos que levam o token actual no corpo (authToken / token)
  // passam por aqui. Se a sessão já venceu antes de enviar, ou se o
  // servidor responde que o token expirou/é inválido, abre-se um login
  // em janela por cima do ecrã (sem apagar o que está na página) e o
  // mesmo pedido é repetido UMA vez com o token novo. Se a pessoa
  // cancelar, a app recebe a resposta original e mostra o erro de
  // sempre. Falhas de rede ("Failed to fetch") não pedem login.
  // ================================================================
  const RX_SESSAO_VENCIDA = /token expirado|token inv[aá]lido|token malformado|assinatura inv[aá]lida|sess[aã]o em falta|sess[aã]o inv[aá]lida|login novamente/i;
  let loginEmCurso = null;   // vários pedidos ao mesmo tempo → uma só janela de login

  function sessaoVencida(data) {
    return !!(data && data.ok === false && RX_SESSAO_VENCIDA.test(String(data.erro || data.error || '')));
  }

  // Abre a janela de login e resolve com o token novo; rejeita se a pessoa cancelar.
  function pedirNovoLogin() {
    if (loginEmCurso) return loginEmCurso;
    loginEmCurso = new Promise(function (resolve, reject) {
      var c = coresTema();
      var modulo = document.body.dataset.fixerosModulo || '';
      var anterior = getUser() || {};
      var fundo = document.createElement('div');
      fundo.id = 'fa-renovar';
      fundo.setAttribute('role', 'dialog');
      fundo.setAttribute('aria-modal', 'true');
      fundo.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:16px;font-family:Outfit,system-ui,sans-serif';
      fundo.innerHTML =
        '<div style="width:100%;max-width:380px;background:' + c.card + ';border:1px solid ' + c.borda + ';border-top:6px solid ' + c.cor + ';border-radius:18px;padding:26px 24px;box-shadow:0 20px 60px rgba(0,0,0,.35)">' +
          '<div style="font-size:19px;font-weight:700;color:' + c.texto + ';margin-bottom:6px">A sessão expirou</div>' +
          '<div style="font-size:13.5px;color:' + c.suave + ';margin-bottom:18px">Entre de novo para continuar. O seu trabalho continua no ecrã e o pedido é repetido sozinho.</div>' +
          '<div style="display:flex;flex-direction:column;gap:12px">' +
            '<input id="fa-r-email" type="email" placeholder="Email" autocomplete="username" style="background:' + c.campo + ';border:1.5px solid ' + c.borda + ';border-radius:10px;color:' + c.texto + ';padding:13px;font-size:14px;outline:none;font-family:inherit"/>' +
            '<input id="fa-r-pass" type="password" placeholder="Palavra-passe" autocomplete="current-password" style="background:' + c.campo + ';border:1.5px solid ' + c.borda + ';border-radius:10px;color:' + c.texto + ';padding:13px;font-size:14px;outline:none;font-family:inherit"/>' +
            '<button id="fa-r-btn" style="background:' + c.cor + ';color:#fff;border:none;border-radius:10px;padding:14px;font-size:14.5px;font-weight:600;cursor:pointer;font-family:inherit">Entrar e continuar</button>' +
            '<button id="fa-r-cancelar" style="background:transparent;color:' + c.suave + ';border:none;padding:6px;font-size:13px;cursor:pointer;font-family:inherit">Cancelar</button>' +
            '<div id="fa-r-erro" style="color:#E5566D;font-size:12.5px;min-height:16px"></div>' +
          '</div>' +
        '</div>';
      document.body.appendChild(fundo);
      var emailEl = fundo.querySelector('#fa-r-email'), passEl = fundo.querySelector('#fa-r-pass');
      var btn = fundo.querySelector('#fa-r-btn'), erroEl = fundo.querySelector('#fa-r-erro');
      emailEl.value = anterior.email || '';
      (anterior.email ? passEl : emailEl).focus();

      function fechar() { fundo.remove(); loginEmCurso = null; }
      async function tentar() {
        erroEl.textContent = '';
        btn.disabled = true; btn.textContent = 'A entrar...';
        try {
          const u = await login(emailEl.value.trim(), passEl.value);
          if (modulo && u.modulos.indexOf(modulo) === -1) {
            limparSessao();
            erroEl.textContent = 'A sua conta não tem acesso a este módulo.';
            btn.disabled = false; btn.textContent = 'Entrar e continuar';
            return;
          }
          fechar();
          // Outra conta = outra empresa: o que está no ecrã não lhe pertence → recomeça a app
          if (anterior.email && u.email && anterior.email.toLowerCase() !== String(u.email).toLowerCase()) { location.reload(); return; }
          resolve(getToken());
        } catch (e) {
          erroEl.textContent = e.message;
          btn.disabled = false; btn.textContent = 'Entrar e continuar';
        }
      }
      btn.addEventListener('click', tentar);
      passEl.addEventListener('keydown', function (e) { if (e.key === 'Enter') tentar(); });
      fundo.querySelector('#fa-r-cancelar').addEventListener('click', function () { fechar(); reject(new Error('Sessão expirada — login cancelado')); });
    });
    return loginEmCurso;
  }

  // Substitui o fetch: só mexe em pedidos cujo corpo (texto) leva o token actual.
  async function fetchVigiado(recurso, opcoes) {
    const tokenUsado = getToken();
    const corpo = opcoes && opcoes.body;
    if (!tokenUsado || typeof corpo !== 'string' || corpo.indexOf(tokenUsado) === -1) return fetchOriginal(recurso, opcoes);
    const comToken = function (t) { return Object.assign({}, opcoes, { body: corpo.split(tokenUsado).join(t) }); };

    // 1) Já se sabe que venceu: pede o login antes de gastar um pedido (e o envio de ficheiros) em vão
    if (!pareceValido()) {
      try { return fetchOriginal(recurso, comToken(await pedirNovoLogin())); }
      catch (e) { return fetchOriginal(recurso, opcoes); }   // cancelou: segue como antes (o servidor recusa)
    }
    // 2) O servidor diz que a sessão não vale (relógio do PC errado, token revogado…)
    const resp = await fetchOriginal(recurso, opcoes);
    let data = null;
    try { data = await resp.clone().json(); } catch (e) { return resp; }
    if (!sessaoVencida(data)) return resp;
    try { return fetchOriginal(recurso, comToken(await pedirNovoLogin())); }
    catch (e) { return resp; }
  }
  window.fetch = fetchVigiado;

  function renderGate(modulo) {
    var c = coresTema(), cor = c.cor;
    var nomes = { fiscal: 'FiscalMoz', reconbank: 'ReconBank', docscan: 'DocScan' };
    var nome = nomes[modulo] || 'Fixer OS';
    document.body.style.background = c.bg;
    document.body.style.margin = '0';
    document.body.style.visibility = 'visible';
    document.body.innerHTML =
      '<div style="min-height:100dvh;display:flex;flex-direction:column;background:' + c.bg + ';font-family:Outfit,system-ui,sans-serif">' +
        '<div style="height:10px;background:' + cor + '"></div>' +
        '<div style="flex:1;display:flex;align-items:center;justify-content:center;padding:20px">' +
          '<div style="width:100%;max-width:380px;background:' + c.card + ';border:1px solid ' + c.borda + ';border-top:6px solid ' + cor + ';border-radius:18px;padding:30px 26px">' +
            '<div style="font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:' + cor + ';margin-bottom:6px">Fixer OS</div>' +
            '<div style="font-size:24px;font-weight:700;color:' + c.texto + ';margin-bottom:4px">' + nome + '</div>' +
            '<div style="font-size:13.5px;color:' + c.suave + ';margin-bottom:22px">Inicie sessão para continuar.</div>' +
            '<div style="display:flex;flex-direction:column;gap:12px">' +
              '<input id="fa-email" type="email" placeholder="Email" autocomplete="username" style="background:' + c.campo + ';border:1.5px solid ' + c.borda + ';border-radius:10px;color:' + c.texto + ';padding:13px;font-size:14px;outline:none;font-family:inherit"/>' +
              '<input id="fa-pass" type="password" placeholder="Palavra-passe" autocomplete="current-password" style="background:' + c.campo + ';border:1.5px solid ' + c.borda + ';border-radius:10px;color:' + c.texto + ';padding:13px;font-size:14px;outline:none;font-family:inherit"/>' +
              '<button id="fa-btn" style="background:' + cor + ';color:#fff;border:none;border-radius:10px;padding:14px;font-size:14.5px;font-weight:600;cursor:pointer;font-family:inherit">Entrar</button>' +
              '<div id="fa-erro" style="color:#E5566D;font-size:12.5px;min-height:16px"></div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    const btn = document.getElementById('fa-btn');
    const emailEl = document.getElementById('fa-email');
    const passEl  = document.getElementById('fa-pass');
    const erroEl  = document.getElementById('fa-erro');

    async function tentar() {
      erroEl.textContent = '';
      btn.disabled = true; btn.textContent = 'A entrar...';
      try {
        const u = await login(emailEl.value.trim(), passEl.value);
        if (modulo && u.modulos.indexOf(modulo) === -1) {
          limparSessao();
          erroEl.textContent = 'A sua conta não tem acesso a este módulo.';
          btn.disabled = false; btn.textContent = 'Entrar';
          return;
        }
        location.reload(); // recarrega para a app principal arrancar normalmente
      } catch (e) {
        erroEl.textContent = e.message;
        btn.disabled = false; btn.textContent = 'Entrar';
      }
    }
    btn.addEventListener('click', tentar);
    passEl.addEventListener('keydown', e => { if (e.key === 'Enter') tentar(); });
  }

  async function exigirLogin(modulo) {
    document.body.dataset.fixerosModulo = modulo;

    // Handoff de SSO — só tenta se ainda não há sessão local válida
    // para este módulo (evita um pedido de rede desnecessário quando
    // a pessoa já está autenticada e simplesmente recarregou a página).
    if (!(pareceValido() && utilizadorTemAcesso(modulo))) {
      await consumirTokenDaURL(modulo);
    }

    if (pareceValido() && utilizadorTemAcesso(modulo)) {
      return getUser();
    }

    limparSessao();
    renderGate(modulo);
    throw new Error('login necessário');
  }

  return { exigirLogin, getToken, getUser, logout };
})();
