(function(){
  const $ = (id) => document.getElementById(id);
  const gate = $('gate');
  const app = $('app');
  const clientIdInput = $('client-id-input');
  const passphraseInput = $('passphrase-input');
  const passphraseGroup = $('passphrase-group');
  const connStatus = $('conn-status');
  const statusDot = $('status-dot');
  const headerStatus = $('header-status');
  const disconnectBtn = $('disconnect-btn');
  const npBody = $('np-body');
  const disc = $('disc');
  const queueList = $('queue-list');
  const searchList = $('search-list');
  const searchInput = $('search-input');
  const toastEl = $('toast');

  // Whatever URL this page is actually running at — no manual redirect-URI editing needed.
  const REDIRECT_URI = window.location.origin + window.location.pathname;

  // Set this to the SHA-256 hex digest of a passphrase to require it before Connect works.
  // Leave empty to disable the passphrase check entirely — the field hides itself too.
  // Generate a hash with:  node -e "console.log(require('crypto').createHash('sha256').update('your passphrase').digest('hex'))"
  // or via powershell: (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('your-pw-here'))) -Algorithm SHA256).Hash.ToLower()
  // this is just a super mundane approach to keep brute forcing out while having a static website.
  const PASSPHRASE_HASH = "";

  async function sha256Hex(str){
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  let pollTimer = null;

  function toast(msg){
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(()=> toastEl.classList.remove('show'), 2400);
  }

  function setConnStatus(msg, cls){
    connStatus.textContent = msg || '';
    connStatus.className = cls || '';
  }

  function esc(s){
    const d = document.createElement('div');
    d.textContent = s == null ? '' : s;
    return d.innerHTML;
  }

  // ---- gate visibility ----
  function showConnected(){
    gate.classList.add('hidden');
    app.classList.remove('hidden');
    headerStatus.classList.add('hidden');
    disconnectBtn.classList.remove('hidden');
    statusDot.classList.add('live');
  }
  function showDisconnected(){
    gate.classList.remove('hidden');
    app.classList.add('hidden');
    headerStatus.classList.remove('hidden');
    headerStatus.textContent = 'not connected';
    disconnectBtn.classList.add('hidden');
    statusDot.classList.remove('live');
  }

  disconnectBtn.addEventListener('click', () => {
    ['sp_client_id','sp_access_token','sp_refresh_token','sp_expires_at','sp_pkce_verifier']
      .forEach(k => localStorage.removeItem(k));
    if(pollTimer) clearInterval(pollTimer);
    clientIdInput.value = '';
    passphraseInput.value = '';
    setConnStatus('');
    showDisconnected();
    toast('Disconnected');
  });

  // ---- PKCE helpers ----
  function randomString(len){
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(len));
    let out = '';
    values.forEach(v => out += possible[v % possible.length]);
    return out;
  }
  async function sha256(plain){
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(plain));
  }
  function base64url(buffer){
    let str = '';
    new Uint8Array(buffer).forEach(b => str += String.fromCharCode(b));
    return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }

  async function beginConnect(){
    const clientId = clientIdInput.value.trim();
    if(!clientId){ toast('Paste a Client ID first'); return; }

    if(PASSPHRASE_HASH){
      const entered = passphraseInput.value;
      const hash = await sha256Hex(entered);
      if(hash !== PASSPHRASE_HASH){
        passphraseInput.value = '';
        setConnStatus('Incorrect passphrase', 'err');
        toast('Incorrect passphrase');
        return;
      }
    }

    localStorage.setItem('sp_client_id', clientId);
    const verifier = randomString(64);
    localStorage.setItem('sp_pkce_verifier', verifier);
    const challenge = base64url(await sha256(verifier));
    const params = new URLSearchParams({
      client_id: clientId,
      response_type: 'code',
      redirect_uri: REDIRECT_URI,
      scope: 'user-read-playback-state user-modify-playback-state',
      code_challenge_method: 'S256',
      code_challenge: challenge
    });
    window.location = 'https://accounts.spotify.com/authorize?' + params.toString();
  }

  function saveTokens(data){
    localStorage.setItem('sp_access_token', data.access_token);
    if(data.refresh_token) localStorage.setItem('sp_refresh_token', data.refresh_token);
    const expiresAt = Date.now() + (data.expires_in * 1000) - 30000;
    localStorage.setItem('sp_expires_at', String(expiresAt));
  }

  async function handleAuthCallback(){
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const err = params.get('error');
    if(err){ setConnStatus('Spotify login failed: ' + err, 'err'); return; }
    if(!code) return;
    const verifier = localStorage.getItem('sp_pkce_verifier');
    const clientId = localStorage.getItem('sp_client_id');
    try{
      const res = await fetch('https://accounts.spotify.com/api/token', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code, redirect_uri: REDIRECT_URI,
          client_id: clientId, code_verifier: verifier
        })
      });
      const data = await res.json();
      if(!data.access_token) throw new Error(data.error_description || 'token exchange failed');
      saveTokens(data);
      window.history.replaceState({}, document.title, window.location.pathname);
      setConnStatus('Connected ✓', 'ok');
      toast('Connected to Spotify');
    }catch(e){
      setConnStatus('Could not connect: ' + e.message, 'err');
    }
  }

  async function ensureAccessToken(){
    const expiresAt = parseInt(localStorage.getItem('sp_expires_at') || '0', 10);
    if(Date.now() < expiresAt) return localStorage.getItem('sp_access_token');

    const refreshToken = localStorage.getItem('sp_refresh_token');
    const clientId = localStorage.getItem('sp_client_id');
    if(!refreshToken || !clientId) throw new Error('no-token');

    const res = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId
      })
    });
    const data = await res.json();
    if(!data.access_token) throw new Error('refresh-failed');
    saveTokens({ ...data, refresh_token: data.refresh_token || refreshToken });
    return data.access_token;
  }

  async function spFetch(path, opts={}){
    const token = await ensureAccessToken();
    const res = await fetch('https://api.spotify.com/v1' + path, {
      ...opts,
      headers: { 'Authorization': 'Bearer ' + token, ...(opts.headers || {}) }
    });
    if(res.status === 401) throw new Error('unauthorized');
    if(res.status === 204) return null;
    if(!res.ok) throw new Error('http-' + res.status);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  // ---- rendering ----
  function renderNowPlaying(playback){
    if(!playback || !playback.item){
      npBody.innerHTML = '<div class="np-empty">Nothing playing right now</div>';
      disc.style.backgroundImage = '';
      disc.classList.remove('spin');
      return;
    }
    const item = playback.item;
    const artists = item.artists.map(a => a.name).join(', ');
    const cover = item.album && item.album.images && item.album.images[0]
      ? item.album.images[0].url : '';
    npBody.innerHTML =
      '<div class="np-title">' + esc(item.name) + '</div>' +
      '<div class="np-artist">' + esc(artists) + '</div>';
    disc.style.backgroundImage = cover ? 'url(' + cover + ')' : '';
    disc.classList.toggle('spin', !!playback.is_playing);
  }

  function renderQueue(items){
    queueList.innerHTML = '';
    if(!items || items.length === 0){
      queueList.innerHTML = '<li class="empty-row">Queue is empty.</li>';
      return;
    }
    items.slice(0, 5).forEach((t, i) => {
      const cover = t.album && t.album.images && t.album.images[2]
        ? t.album.images[2].url : (t.album && t.album.images && t.album.images[0] ? t.album.images[0].url : '');
      const artists = t.artists.map(a => a.name).join(', ');
      const li = document.createElement('li');
      li.className = 'track';
      li.innerHTML =
        '<span class="q-num">' + String(i+1).padStart(2,'0') + '</span>' +
        (cover ? '<img src="' + cover + '" alt="">' : '<img alt="">') +
        '<div class="meta"><div class="t-name">' + esc(t.name) + '</div>' +
        '<div class="t-artist">' + esc(artists) + '</div></div>';
      queueList.appendChild(li);
    });
  }

  async function refresh(){
    try{
      const playback = await spFetch('/me/player');
      renderNowPlaying(playback);
    }catch(e){
      if(e.message === 'unauthorized') toast('Token expired — reconnect above');
      renderNowPlaying(null);
    }
    try{
      const q = await spFetch('/me/player/queue');
      renderQueue(q ? q.queue : []);
    }catch(e){
      renderQueue([]);
    }
  }

  function startPolling(){
    if(pollTimer) clearInterval(pollTimer);
    refresh();
    pollTimer = setInterval(refresh, 5000);
  }

  $('connect-btn').addEventListener('click', beginConnect);
  clientIdInput.addEventListener('keydown', (e) => { if(e.key === 'Enter') beginConnect(); });
  passphraseInput.addEventListener('keydown', (e) => { if(e.key === 'Enter') beginConnect(); });

  async function runSearch(){
    const q = searchInput.value.trim();
    if(!q) return;
    searchList.innerHTML = '<li class="empty-row">Searching…</li>';
    try{
      const data = await spFetch('/search?type=track&limit=8&q=' + encodeURIComponent(q));
      const tracks = (data && data.tracks && data.tracks.items) || [];
      if(tracks.length === 0){
        searchList.innerHTML = '<li class="empty-row">No results.</li>';
        return;
      }
      searchList.innerHTML = '';
      tracks.forEach(t => {
        const cover = t.album && t.album.images && t.album.images[2]
          ? t.album.images[2].url : (t.album && t.album.images && t.album.images[0] ? t.album.images[0].url : '');
        const artists = t.artists.map(a => a.name).join(', ');
        const li = document.createElement('li');
        li.className = 'track';
        li.innerHTML =
          (cover ? '<img src="' + cover + '" alt="">' : '<img alt="">') +
          '<div class="meta"><div class="t-name">' + esc(t.name) + '</div>' +
          '<div class="t-artist">' + esc(artists) + '</div></div>' +
          '<button class="add-btn" data-uri="' + t.uri + '">Add</button>';
        searchList.appendChild(li);
      });
    }catch(e){
      searchList.innerHTML = '<li class="empty-row">Search failed — check your connection.</li>';
    }
  }

  $('search-btn').addEventListener('click', runSearch);
  searchInput.addEventListener('keydown', (e) => { if(e.key === 'Enter') runSearch(); });

  searchList.addEventListener('click', async (e) => {
    const btn = e.target.closest('.add-btn');
    if(!btn) return;
    const uri = btn.dataset.uri;
    btn.disabled = true;
    btn.textContent = '…';
    try{
      await spFetch('/me/player/queue?uri=' + encodeURIComponent(uri), { method: 'POST' });
      btn.textContent = 'Added';
      toast('Added to queue');
      setTimeout(refresh, 800);
    }catch(err){
      btn.disabled = false;
      btn.textContent = 'Add';
      toast('Could not add — is something playing on an active device?');
    }
  });

  // ---- init ----
  (async function init(){
    if(!PASSPHRASE_HASH){
      passphraseGroup.classList.add('hidden');
    }

    const savedClientId = localStorage.getItem('sp_client_id');
    if(savedClientId) clientIdInput.value = savedClientId;

    await handleAuthCallback();

    if(localStorage.getItem('sp_refresh_token')){
      showConnected();
      startPolling();
    }else{
      showDisconnected();
    }
  })();
})();
