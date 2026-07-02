/* ================================================================
   FIXER OS — fixeros-auth.js (v1.1)
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

  async function login(email, password) {
    const resp = await fetch(AUTH_GAS_URL, {
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
      const resp = await fetch(AUTH_GAS_URL, {
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
        email: data.email, empresa: data.empresa, role: data.role, modulos: data.modulos
      }));
      return true;
    } catch (e) {
      // Falha de rede a validar — mais seguro tratar como handoff
      // falhado do que confiar num token nunca verificado.
      return false;
    }
  }

  function renderGate(modulo) {
    document.body.innerHTML = `
      <div style="min-height:100dvh;display:flex;align-items:center;justify-content:center;
                  background:#0A1628;font-family:system-ui,sans-serif;padding:20px">
        <div style="width:100%;max-width:360px;background:#0F2040;border:1px solid #1E3A6E;
                    border-radius:18px;padding:28px 24px">
          <div style="font-size:20px;font-weight:800;color:#E8F0FF;margin-bottom:4px">Fixer OS</div>
          <div style="font-size:12px;color:#7B9CC8;margin-bottom:24px;font-family:monospace">
            Acesso — módulo: ${modulo || '—'}
          </div>
          <div style="display:flex;flex-direction:column;gap:12px">
            <input id="fa-email" type="email" placeholder="Email" autocomplete="username"
              style="background:#162B52;border:1px solid #254880;border-radius:8px;color:#E8F0FF;
                     padding:12px;font-size:14px;outline:none"/>
            <input id="fa-pass" type="password" placeholder="Password" autocomplete="current-password"
              style="background:#162B52;border:1px solid #254880;border-radius:8px;color:#E8F0FF;
                     padding:12px;font-size:14px;outline:none"/>
            <button id="fa-btn"
              style="background:linear-gradient(135deg,#1558AA,#1A6FD4);color:#fff;border:none;
                     border-radius:8px;padding:13px;font-size:14px;font-weight:700;cursor:pointer">
              Entrar
            </button>
            <div id="fa-erro" style="color:#EF4444;font-size:12px;min-height:16px"></div>
          </div>
        </div>
      </div>`;

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
          erroEl.textContent = 'A tua conta não tem acesso ao módulo "' + modulo + '".';
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
