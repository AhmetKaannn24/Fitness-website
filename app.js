/* =========================================================
   FORGE — entry point
   Modüller:
     js/router.js          → SPA yönlendirme
     js/api.js             → veri katmanı (localStorage / fetch)
     js/tools.js           → hesaplama araçları kataloğu
     js/ui.js              → toast, modal, spinner, format yardımcıları
     js/errors.js          → merkezi hata yönetimi (handleError + global)
     js/views/*.js         → her sayfa için ayrı render modülü

   auth.js (kök dizinde) klasik script olarak önce yüklenir ve
   window.forge.apiFetch'i sağlar; bu modüller backend'e geçişte
   api.js içinden onu kullanır.
   ========================================================= */

import { initRouter, setRoute } from './js/router.js';
import * as api from './js/api.js';
import { toast, confirmModal, setBtnLoading } from './js/ui.js';
import { handleError, installGlobalErrorHandlers } from './js/errors.js';
import { log } from './js/logger.js';   // window.forge.log global'ini de kurar

// ============== GLOBAL: Beklenmeyen hata yakalayıcılar ==============
// Promise rejection + window.onerror — istisnasız hiçbir hata sessizce kaybolmaz.
installGlobalErrorHandlers();

// ============== ADMIN nav görünürlüğü ==============
function syncAdminNav() {
  const link = document.getElementById('nav-admin');
  if (!link) return;
  const isAdmin = window.forge?.auth?.user?.role === 'admin';
  link.classList.toggle('hidden', !isAdmin);
}
syncAdminNav();
window.forge?.auth?.onChange?.(syncAdminNav);

// ============== GLOBAL: Tüm verileri sıfırla ==============
document.getElementById('wipe-all')?.addEventListener('click', async ev => {
  const ok = await confirmModal(
    'Tümünü Sıfırla',
    'Tüm program, antrenman ve hesaplama verilerin silinecek. Bu işlem geri alınamaz.'
  );
  if (!ok) return;

  const btn = ev.currentTarget;
  setBtnLoading(btn, true, 'Siliniyor...');
  try {
    await api.wipeAll();
    log('user.wipe', 'Kullanıcı tüm verileri sıfırladı', null, 'warn');
    toast('Tüm veriler silindi', 'success');
    setRoute('dashboard');
  } catch (err) {
    handleError(err, 'wipe');
  } finally {
    setBtnLoading(btn, false);
  }
});

// ============== BOOT ==============
try {
  initRouter();
  setRoute('dashboard');
} catch (err) {
  handleError(err, 'default');
}
