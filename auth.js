/* =========================================================
   FORGE — Auth katmanı
   - JWT alır, sessionStorage/localStorage'da saklar
   - apiFetch: tüm isteklere Authorization: Bearer header'ı ekler
   - 401 → otomatik logout + login ekranı
   - Token süresi dolduğunda proaktif logout
   ========================================================= */

(() => {
  // ---- KONFİG ----
  const API_BASE = (window.FORGE_API_BASE || 'http://localhost:5080/api').replace(/\/$/, '');
  const TOKEN_KEY = 'forge.auth.v1';
  const USERS_KEY = 'forge.users.v1';
  // Remember-me kapalıyken sessionStorage, açıkken localStorage kullanılır.

  // ============================================================
  // YEREL KULLANICI MAĞAZASI (backend yokken devreye girer)
  // Admin/admin hesabı boot'ta otomatik oluşturulur.
  // NOT: Demo amaçlı şifreler düz tutulur — yalnızca tarayıcıda kalır.
  // ============================================================
  function getLocalUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || []; }
    catch { return []; }
  }
  function saveLocalUsers(arr) {
    localStorage.setItem(USERS_KEY, JSON.stringify(arr));
  }
  function ensureAdminUser() {
    const users = getLocalUsers();
    if (users.some(u => u.username === 'admin')) return;
    users.push({
      id: 'admin',
      username: 'admin',
      email: 'admin@forge.local',
      password: 'admin',
      displayName: 'Yönetici',
      role: 'admin',
      createdAt: new Date().toISOString()
    });
    saveLocalUsers(users);
  }
  ensureAdminUser();

  function localRegister(req) {
    const users = getLocalUsers();
    const uname = req.username.trim();
    const email = (req.email || '').trim().toLowerCase();

    if (users.some(u => u.username.toLowerCase() === uname.toLowerCase())) {
      const err = new Error('Bu kullanıcı adı zaten alınmış.');
      err.status = 409; throw err;
    }
    if (users.some(u => u.email.toLowerCase() === email)) {
      const err = new Error('Bu e-posta zaten kayıtlı.');
      err.status = 409; throw err;
    }
    const user = {
      id: 'u_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      username: uname,
      email,
      password: req.password,           // demo amaçlı; tarayıcı içinde kalır
      displayName: req.displayName || null,
      role: 'user',
      createdAt: new Date().toISOString()
    };
    users.push(user);
    saveLocalUsers(users);
    return buildLocalAuth(user);
  }

  function localLogin(req) {
    const users = getLocalUsers();
    const id = (req.identifier || '').trim().toLowerCase();
    const user = users.find(u =>
      u.username.toLowerCase() === id || (u.email && u.email.toLowerCase() === id)
    );
    if (!user || user.password !== req.password) {
      const err = new Error('E-posta/kullanıcı adı veya şifre hatalı.');
      err.status = 401; throw err;
    }
    return buildLocalAuth(user);
  }

  function buildLocalAuth(user) {
    const safe = { ...user }; delete safe.password;
    return {
      accessToken: 'local_' + Math.random().toString(36).slice(2) + Date.now().toString(36),
      tokenType: 'Local',
      expiresAtUtc: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
      user: safe
    };
  }

  // ===================== STORAGE =====================
  function readToken() {
    try {
      const raw = sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY);
      if (!raw) return null;
      const data = JSON.parse(raw);
      if (!data?.accessToken || !data?.expiresAtUtc) return null;
      if (new Date(data.expiresAtUtc).getTime() <= Date.now()) {
        clearToken();
        return null;
      }
      return data;
    } catch { return null; }
  }
  function writeToken(data, remember) {
    const json = JSON.stringify(data);
    // Önce her iki yeri de temizle ki çift kayıt olmasın.
    sessionStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(TOKEN_KEY);
    (remember ? localStorage : sessionStorage).setItem(TOKEN_KEY, json);
  }
  function clearToken() {
    sessionStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(TOKEN_KEY);
  }

  // ===================== STATE =====================
  const state = {
    token: null,
    user: null,
    expiresAtUtc: null,
    listeners: new Set()
  };
  function emit() { state.listeners.forEach(fn => { try { fn(state); } catch {} }); }

  // ===================== FETCH INTERCEPTOR =====================
  /**
   * Tüm API çağrılarının gitmesi gereken yer.
   * - Mutlak veya göreceli URL ('/users' ya da 'http://...') kabul eder.
   * - JSON body'yi otomatik stringify eder.
   * - Bearer token ekler.
   * - 401 alındığında session'ı temizler ve login ekranını gösterir.
   */
  async function apiFetch(path, options = {}) {
    const url = path.startsWith('http')
      ? path
      : API_BASE + (path.startsWith('/') ? path : '/' + path);

    const headers = new Headers(options.headers || {});
    if (!headers.has('Accept')) headers.set('Accept', 'application/json');
    if (state.token) headers.set('Authorization', 'Bearer ' + state.token);

    // Body objelerini otomatik serialize et
    let body = options.body;
    const isPlainObj = body && typeof body === 'object'
      && !(body instanceof FormData)
      && !(body instanceof Blob)
      && !(body instanceof ArrayBuffer);
    if (isPlainObj) {
      body = JSON.stringify(body);
      if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    }

    let res;
    try {
      res = await fetch(url, { ...options, headers, body });
    } catch (e) {
      // Ağ hatası — auth ekranını tetiklemiyoruz; çağıran tarafa fırlatıyoruz.
      throw new NetworkError('Sunucuya ulaşılamadı.', e);
    }

    if (res.status === 401) {
      // Token reddedildi → tüm oturumu sıfırla.
      auth.logout({ silent: true });
      throw new ApiError(401, 'Oturumun sona erdi. Lütfen tekrar giriş yap.');
    }

    if (res.status === 204) return null;

    const contentType = res.headers.get('content-type') || '';
    const payload = contentType.includes('application/json')
      ? await res.json().catch(() => null)
      : await res.text();

    if (!res.ok) {
      const msg = (payload && payload.error)
        || (payload && payload.title)
        || res.statusText
        || 'İstek başarısız.';
      throw new ApiError(res.status, msg, payload);
    }
    return payload;
  }

  class ApiError extends Error {
    constructor(status, message, payload) {
      super(message); this.name = 'ApiError'; this.status = status; this.payload = payload;
    }
  }
  class NetworkError extends Error {
    constructor(message, cause) { super(message); this.name = 'NetworkError'; this.cause = cause; }
  }

  // ---- Auth-özel hata çevirici (errors.js'in mini sürümü) ----
  function translateAuthError(err, ctx) {
    if (!err) return 'Bilinmeyen hata.';
    if (err.name === 'NetworkError') {
      return 'Sunucuya ulaşılamıyor. Bağlantını kontrol et.';
    }
    if (typeof err.status === 'number') {
      if (ctx === 'login' && err.status === 401) return 'E-posta veya şifre hatalı.';
      if (ctx === 'register' && err.status === 409) return 'Bu kullanıcı adı veya e-posta zaten kayıtlı.';
      if (ctx === 'register' && err.status === 400) return err.message || 'Kayıt bilgileri geçersiz.';
      if (err.status === 400) return err.message || 'Geçersiz veri.';
      if (err.status >= 500) return 'Sunucu hatası. Daha sonra tekrar dene.';
      if (err.status === 429) return 'Çok fazla deneme. Lütfen biraz bekle.';
    }
    return err.message || (ctx === 'login' ? 'Giriş başarısız.' : 'Kayıt başarısız.');
  }

  // ---- Inline button spinner (modül-dışı; ui.js'e bağımlılık olmasın) ----
  function toggleBtnSpinner(btn, on, loadingText) {
    if (!btn) return;
    if (on) {
      if (btn.dataset.loading === '1') return;
      btn.dataset.loading = '1';
      btn.dataset.original = btn.innerHTML;
      btn.disabled = true;
      btn.classList.add('is-loading');
      btn.innerHTML =
        '<span class="spinner" role="status" aria-label="Yükleniyor"></span>' +
        '<span class="btn-loading-text">' + (loadingText || 'Yükleniyor...') + '</span>';
    } else {
      if (btn.dataset.loading !== '1') return;
      btn.disabled = false;
      btn.classList.remove('is-loading');
      btn.innerHTML = btn.dataset.original ?? btn.innerHTML;
      delete btn.dataset.loading;
      delete btn.dataset.original;
    }
  }

  // ===================== AUTH API =====================
  const auth = {
    get token() { return state.token; },
    get user() { return state.user; },
    get isAuthenticated() { return !!state.token; },

    onChange(fn) { state.listeners.add(fn); return () => state.listeners.delete(fn); },

    async register({ username, email, password, displayName, remember = true }) {
      let data;
      try {
        data = await apiFetch('/auth/register', {
          method: 'POST',
          body: { username, email, password, displayName }
        });
      } catch (e) {
        // Backend ulaşılamıyorsa yerel mağazaya düş.
        if (e?.name !== 'NetworkError') throw e;
        data = localRegister({ username, email, password, displayName });
      }
      applyAuthData(data, remember);
      window.forge?.log?.('auth.register',
        `Yeni kullanıcı: ${data.user.username}`,
        { id: data.user.id, mode: data.tokenType === 'Local' ? 'local' : 'api' },
        'success');
      return data;
    },

    async login({ identifier, password, remember = true }) {
      let data;
      try {
        data = await apiFetch('/auth/login', {
          method: 'POST',
          body: { identifier, password }
        });
      } catch (e) {
        if (e?.name !== 'NetworkError') throw e;
        data = localLogin({ identifier, password });
      }
      applyAuthData(data, remember);
      window.forge?.log?.('auth.login',
        `Giriş: ${data.user.username}`,
        { id: data.user.id, role: data.user.role, mode: data.tokenType === 'Local' ? 'local' : 'api' },
        'info');
      return data;
    },

    async refreshMe() {
      if (!state.token) return null;
      try {
        const user = await apiFetch('/auth/me');
        state.user = user;
        // Kayıtlı veriyi güncelle (user değiştiyse).
        persistCurrent();
        emit();
        return user;
      } catch (e) {
        if (e?.status === 401) return null;
        throw e;
      }
    },

    logout({ silent = false } = {}) {
      const who = state.user?.username;
      clearToken();
      state.token = null;
      state.user = null;
      state.expiresAtUtc = null;
      emit();
      if (who) window.forge?.log?.('auth.logout', `Çıkış: ${who}`, null, 'info');
      if (!silent) ui.showAuthScreen('Çıkış yapıldı.');
      else ui.showAuthScreen();
    },

    // Yerel kullanıcı yönetimi (admin paneli kullanır)
    getLocalUsers,
    deleteLocalUser(userId) {
      if (userId === 'admin') throw new Error('Admin hesabı silinemez.');
      const users = getLocalUsers().filter(u => u.id !== userId);
      saveLocalUsers(users);
      window.forge?.log?.('admin.user.delete', `Kullanıcı silindi: ${userId}`, { userId }, 'warn');
    }
  };

  function applyAuthData(data, remember) {
    state.token = data.accessToken;
    state.user = data.user;
    state.expiresAtUtc = data.expiresAtUtc;
    writeToken({
      accessToken: data.accessToken,
      expiresAtUtc: data.expiresAtUtc,
      user: data.user
    }, remember);
    scheduleAutoLogout();
    emit();
  }
  function persistCurrent() {
    const persisted = readToken(); // hangi storage'da olduğunu bilelim
    const useLocal = !!localStorage.getItem(TOKEN_KEY);
    writeToken({
      accessToken: state.token,
      expiresAtUtc: state.expiresAtUtc,
      user: state.user
    }, useLocal);
  }

  let autoLogoutTimer = null;
  function scheduleAutoLogout() {
    if (autoLogoutTimer) clearTimeout(autoLogoutTimer);
    if (!state.expiresAtUtc) return;
    const ms = new Date(state.expiresAtUtc).getTime() - Date.now() - 1000;
    if (ms <= 0) { auth.logout({ silent: true }); return; }
    // setTimeout maksimum ~24.8 gün; bizim token kısa süreli, sorun yok.
    autoLogoutTimer = setTimeout(() => auth.logout({ silent: true }), ms);
  }

  // ===================== UI BINDING =====================
  const ui = {
    elements() {
      return {
        overlay: document.getElementById('auth-overlay'),
        loginForm: document.getElementById('login-form'),
        registerForm: document.getElementById('register-form'),
        tabs: document.querySelectorAll('.auth-tab'),
        message: document.getElementById('auth-message'),
        appWrap: document.getElementById('app-wrap'),
        userChip: document.getElementById('user-chip'),
        userChipName: document.getElementById('user-chip-name'),
        logoutBtn: document.getElementById('logout-btn')
      };
    },
    showAuthScreen(msg = '') {
      const e = this.elements();
      if (e.overlay) e.overlay.classList.remove('hidden');
      if (e.appWrap) e.appWrap.classList.add('hidden');
      if (e.userChip) e.userChip.classList.add('hidden');
      this.setMessage(msg);
    },
    showApp() {
      const e = this.elements();
      if (e.overlay) e.overlay.classList.add('hidden');
      if (e.appWrap) e.appWrap.classList.remove('hidden');
      if (e.userChip) e.userChip.classList.remove('hidden');
      if (e.userChipName) e.userChipName.textContent =
        state.user?.displayName || state.user?.username || state.user?.email || '';
      this.setMessage('');
    },
    setMessage(text, kind = 'info') {
      const el = document.getElementById('auth-message');
      if (!el) return;
      el.textContent = text || '';
      el.dataset.kind = kind;
      el.classList.toggle('hidden', !text);
    },
    switchTab(which) {
      const e = this.elements();
      e.tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === which));
      e.loginForm?.classList.toggle('hidden', which !== 'login');
      e.registerForm?.classList.toggle('hidden', which !== 'register');
      this.setMessage('');
    },
    bindOnce() {
      const e = this.elements();
      e.tabs.forEach(t => t.addEventListener('click', () => this.switchTab(t.dataset.tab)));

      e.loginForm?.addEventListener('submit', async ev => {
        ev.preventDefault();
        const fd = new FormData(e.loginForm);
        const submitBtn = e.loginForm.querySelector('button[type="submit"]');
        toggleBtnSpinner(submitBtn, true, 'Giriş yapılıyor...');
        try {
          this.setMessage('Giriş yapılıyor...');
          await auth.login({
            identifier: fd.get('identifier').toString().trim(),
            password: fd.get('password').toString(),
            remember: fd.get('remember') === 'on'
          });
          this.showApp();
        } catch (err) {
          this.setMessage(translateAuthError(err, 'login'), 'error');
        } finally {
          toggleBtnSpinner(submitBtn, false);
        }
      });

      e.registerForm?.addEventListener('submit', async ev => {
        ev.preventDefault();
        const fd = new FormData(e.registerForm);
        const submitBtn = e.registerForm.querySelector('button[type="submit"]');
        toggleBtnSpinner(submitBtn, true, 'Kayıt oluşturuluyor...');
        try {
          this.setMessage('Kayıt oluşturuluyor...');
          await auth.register({
            username: fd.get('username').toString().trim(),
            email: fd.get('email').toString().trim(),
            password: fd.get('password').toString(),
            displayName: fd.get('displayName')?.toString().trim() || null,
            remember: fd.get('remember') === 'on'
          });
          this.showApp();
        } catch (err) {
          this.setMessage(translateAuthError(err, 'register'), 'error');
        } finally {
          toggleBtnSpinner(submitBtn, false);
        }
      });

      e.logoutBtn?.addEventListener('click', () => auth.logout());
    }
  };

  // ===================== BOOTSTRAP =====================
  function boot() {
    ui.bindOnce();
    const cached = readToken();
    if (cached) {
      state.token = cached.accessToken;
      state.user = cached.user;
      state.expiresAtUtc = cached.expiresAtUtc;
      scheduleAutoLogout();
      ui.showApp();
      // Arka planda profil tazele
      auth.refreshMe().catch(() => {});
    } else {
      ui.showAuthScreen();
    }
    emit();
  }

  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', boot);
  else boot();

  // ===================== GLOBAL EXPORT =====================
  window.forge = window.forge || {};
  window.forge.auth = auth;
  window.forge.apiFetch = apiFetch;
  window.forge.api = {
    get:  (p)    => apiFetch(p),
    post: (p, b) => apiFetch(p, { method: 'POST', body: b }),
    put:  (p, b) => apiFetch(p, { method: 'PUT', body: b }),
    del:  (p)    => apiFetch(p, { method: 'DELETE' })
  };
  window.forge.ApiError = ApiError;
  window.forge.NetworkError = NetworkError;
})();
