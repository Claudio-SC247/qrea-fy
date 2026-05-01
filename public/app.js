/* ══ TEMA ═══════════════════════════════════════════════════════════════════ */
const html    = document.documentElement;
const modeBtn = document.getElementById('mode-btn');

function applyTheme(t) {
  html.setAttribute('data-theme', t);
  modeBtn.textContent = t === 'dark' ? '🌙' : '☀️';
  const meta = document.getElementById('theme-color-meta');
  if (meta) meta.content = t === 'dark' ? '#060610' : '#f4f4ff';
  localStorage.setItem('qreafy-theme', t);
}
function toggleMode() {
  applyTheme(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}
(function () {
  const saved = localStorage.getItem('qreafy-theme');
  applyTheme(saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
})();
modeBtn.addEventListener('click', toggleMode);
document.getElementById('mode-btn').addEventListener('click', toggleMode); // alias for validator

/* ══ TABS ════════════════════════════════════════════════════════════════════ */
function go(id, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('on'));
  document.querySelectorAll('.tab').forEach(b => { b.classList.remove('on'); b.setAttribute('aria-selected','false'); });
  document.getElementById('p-' + id).classList.add('on');
  btn.classList.add('on');
  btn.setAttribute('aria-selected','true');
  if (id === 'url') loadHistory();
}
document.getElementById('tab-qr').addEventListener('click', function () { go('qr', this); });
document.getElementById('tab-url').addEventListener('click', function () { go('url', this); });

/* ══ TOAST ═══════════════════════════════════════════════════════════════════ */
let _tt;
function toast(msg, type='ok') {
  const el = document.getElementById('toast');
  document.getElementById('t-msg').textContent = msg;
  document.getElementById('t-ico').textContent = {ok:'✓',er:'✕',info:'◈'}[type]||'◈';
  el.className = 'toast on ' + type;
  clearTimeout(_tt); _tt = setTimeout(() => el.classList.remove('on'), 3200);
}

/* ══ ERRORS ══════════════════════════════════════════════════════════════════ */
function showErr(id, msg) { const e=document.getElementById(id); e.textContent=msg; e.classList.add('on'); }
function clrErr(id)       { const e=document.getElementById(id); e.textContent=''; e.classList.remove('on'); }
function showRate(id)     { document.getElementById(id).classList.add('on'); }
function hideRate(id)     { document.getElementById(id).classList.remove('on'); }

/* ══ SLIDERS ═════════════════════════════════════════════════════════════════ */
document.getElementById('sz').addEventListener('input', function () { document.getElementById('sv').textContent = this.value; });
document.getElementById('bd').addEventListener('input', function () { document.getElementById('bv').textContent = this.value; });
document.getElementById('lr').addEventListener('input', function () { document.getElementById('rv').textContent = this.value; });

/* ══ LOGO ════════════════════════════════════════════════════════════════════ */
function onLogo(file) {
  if (!file) return;
  if (file.size > 3*1024*1024) { toast('Máx. 3 MB','er'); return; }
  if (!['image/png','image/jpeg','image/gif','image/webp'].includes(file.type)) { toast('Formato no permitido','er'); return; }
  const r = new FileReader();
  r.onload = e => { const p=document.getElementById('logo-prev'); p.src=e.target.result; p.style.display='block'; };
  r.readAsDataURL(file);
}
function clearLogo() {
  document.getElementById('logo-file').value='';
  const p=document.getElementById('logo-prev'); p.src=''; p.style.display='none';
}
document.getElementById('logo-file').addEventListener('change', function () { if(this.files[0]) onLogo(this.files[0]); });
document.getElementById('btn-clear-logo').addEventListener('click', clearLogo);

const dz = document.getElementById('dz');
dz.addEventListener('dragover', e=>{ e.preventDefault(); dz.classList.add('over'); });
dz.addEventListener('dragleave', ()=>dz.classList.remove('over'));
dz.addEventListener('drop', e=>{
  e.preventDefault(); dz.classList.remove('over');
  const f=e.dataTransfer.files[0];
  if(f){ const dt=new DataTransfer(); dt.items.add(f); document.getElementById('logo-file').files=dt.files; onLogo(f); }
});

/* ══ QR GENERATOR ════════════════════════════════════════════════════════════ */
let lastQR = null;
async function genQR() {
  clrErr('qr-err'); hideRate('qr-rate');
  const data = document.getElementById('qr-data').value.trim();
  if (!data) { showErr('qr-err','⚠ Ingresa una URL o texto.'); return; }
  if (data.length>2000) { showErr('qr-err','⚠ Máx. 2000 caracteres.'); return; }
  const btn=document.getElementById('btn-gen'), sp=document.getElementById('sp-qr');
  btn.disabled=true; sp.style.display='inline-block';
  const fd=new FormData();
  fd.append('data', data);
  fd.append('size', document.getElementById('sz').value);
  fd.append('border', document.getElementById('bd').value);
  fd.append('fill_color', document.getElementById('fill').value);
  fd.append('back_color', document.getElementById('back').value);
  fd.append('logo_ratio', (document.getElementById('lr').value/100).toFixed(2));
  const li=document.getElementById('logo-file');
  if(li.files.length>0) fd.append('logo', li.files[0]);
  try {
    const res=await fetch('/api/generate-qr',{method:'POST',body:fd});
    if(res.status===429){showRate('qr-rate');return;}
    const json=await res.json();
    if(json.error){showErr('qr-err','✕ '+json.error);return;}
    lastQR='data:image/png;base64,'+json.qr;
    const img=document.getElementById('qr-img');
    img.src=lastQR; img.style.display='block';
    document.getElementById('qr-ph').style.display='none';
    document.getElementById('qr-acts').style.display='flex';
    toast('¡QR generado!','ok');
  } catch { showErr('qr-err','✕ Error de conexión.'); }
  finally { btn.disabled=false; sp.style.display='none'; }
}
function dlQR() {
  if(!lastQR) return;
  const a=document.createElement('a'); a.href=lastQR; a.download='qreafy-'+Date.now()+'.png'; a.click();
  toast('Descarga iniciada','ok');
}
async function cpQR() {
  if(!lastQR) return;
  try { const blob=await(await fetch(lastQR)).blob(); await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]); toast('Imagen copiada','ok'); }
  catch { toast('Usa el botón descargar','er'); }
}
document.getElementById('btn-gen').addEventListener('click', genQR);
document.getElementById('btn-dl-qr').addEventListener('click', dlQR);
document.getElementById('btn-cp-qr').addEventListener('click', cpQR);

/* ══ URL SHORTENER ═══════════════════════════════════════════════════════════ */
async function shortenURL() {
  clrErr('url-err'); hideRate('url-rate');
  const url=document.getElementById('long-url').value.trim();
  if(!url){showErr('url-err','⚠ Ingresa una URL.');return;}
  const btn=document.getElementById('btn-short'), sp=document.getElementById('sp-url');
  btn.disabled=true; sp.style.display='inline-block';
  try {
    const res=await fetch('/api/shorten-url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    if(res.status===429){showRate('url-rate');return;}
    const json=await res.json();
    if(json.error){showErr('url-err','✕ '+json.error);return;}
    document.getElementById('r-short').textContent=json.short_url;
    document.getElementById('r-orig').textContent=json.original_url;
    document.getElementById('url-res').classList.add('on');
    updateKvBadge(json.kv);
    lsPush({short_url:json.short_url,original_url:json.original_url,ts:json.ts||Date.now()});
    await loadHistory();
    toast('URL acortada ✓','ok');
  } catch { showErr('url-err','✕ Error de conexión.'); }
  finally { btn.disabled=false; sp.style.display='none'; }
}
document.getElementById('btn-short').addEventListener('click', shortenURL);

/* ══ HISTORY ═════════════════════════════════════════════════════════════════ */
const LS_KEY='qreafy:history', LS_MAX=100;
function lsLoad() { try{return JSON.parse(localStorage.getItem(LS_KEY)||'[]');}catch{return[];} }
function lsSave(i) { try{localStorage.setItem(LS_KEY,JSON.stringify(i.slice(0,LS_MAX)));}catch{} }
function lsPush(item) { const items=lsLoad(); lsSave([item,...items.filter(i=>i.short_url!==item.short_url)]); }
function lsClear() { try{localStorage.removeItem(LS_KEY);}catch{} }

async function loadHistory() {
  const local=lsLoad();
  if(local.length) renderHist(local);
  try {
    const res=await fetch('/api/history');
    if(!res.ok) return;
    const json=await res.json();
    updateKvBadge(json.kv_available);
    const server=json.history||[];
    if(server.length){
      const seen=new Set();
      const merged=[...server,...local].filter(i=>{ if(seen.has(i.short_url))return false; seen.add(i.short_url); return true; });
      lsSave(merged); renderHist(merged);
    } else if(local.length){ renderHist(local); }
    else { renderHist([]); }
  } catch {}
}
async function clearHistory() {
  lsClear(); renderHist([]); toast('Historial limpiado','ok');
  try { await fetch('/api/history',{method:'DELETE'}); } catch {}
}
document.getElementById('btn-clear-hist').addEventListener('click', clearHistory);

function updateKvBadge(available) {
  const b=document.getElementById('kv-badge');
  if(available){b.textContent='⬤ persistente';b.className='kv-badge kv-on';}
  else{b.textContent='⬤ local';b.className='kv-badge kv-off';}
}
function renderHist(items) {
  const ul=document.getElementById('hist');
  const count=document.getElementById('hist-count');
  const statsBar=document.getElementById('stats-bar');
  while(ul.firstChild) ul.removeChild(ul.firstChild);
  if(!items.length){
    const li=document.createElement('li'); li.id='hist-empty'; li.className='hist-empty-msg';
    li.textContent='Tus URLs acortadas aparecerán aquí';
    ul.appendChild(li); count.textContent=''; statsBar.classList.add('hidden'); return;
  }
  count.textContent=`${items.length} enlace${items.length!==1?'s':''}`;
  statsBar.classList.remove('hidden');
  document.getElementById('stat-total').textContent=items.length;
  const today=items.filter(h=>h.ts&&Date.now()-h.ts<86400000).length;
  document.getElementById('stat-today').textContent=today||items.length;
  items.forEach(h=>{
    const li=document.createElement('li'); li.className='hist-item';
    const s=document.createElement('span'); s.className='h-short'; s.textContent=h.short_url;
    const o=document.createElement('span'); o.className='h-orig'; o.textContent=h.original_url; o.title=h.original_url;
    const b=document.createElement('button'); b.className='cp-btn h-cp btn-sm'; b.textContent='⎘'; b.setAttribute('aria-label','Copiar');
    b.addEventListener('click',()=>cpText(h.short_url,b));
    li.append(s,o,b); ul.appendChild(li);
  });
}

/* ══ COPY ════════════════════════════════════════════════════════════════════ */
function cpURL() { cpText(document.getElementById('r-short').textContent, document.getElementById('cp-main')); }
function cpText(txt,btn) {
  navigator.clipboard.writeText(txt).then(()=>{
    if(btn){btn.classList.add('done');setTimeout(()=>btn.classList.remove('done'),1800);}
    toast('Copiado','ok');
  }).catch(()=>toast('No se pudo copiar','er'));
}
function urlToQR() {
  document.getElementById('qr-data').value=document.getElementById('r-short').textContent;
  go('qr',document.getElementById('tab-qr'));
  toast('URL cargada en el generador','info');
}
document.getElementById('cp-main').addEventListener('click', cpURL);
document.getElementById('btn-url-to-qr').addEventListener('click', urlToQR);

/* ══ ENTER KEY ═══════════════════════════════════════════════════════════════ */
document.getElementById('long-url').addEventListener('keydown',e=>{if(e.key==='Enter')shortenURL();});
document.getElementById('qr-data').addEventListener('keydown',e=>{if(e.key==='Enter')genQR();});

/* ══ INIT ════════════════════════════════════════════════════════════════════ */
loadHistory();
