// ===== Utilitários gerais =====

function b64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function concatBytes(...arrs) {
  const len = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const a of arrs) { out.set(a, offset); offset += a.length; }
  return out;
}

async function checkPinWithLockout(request, env) {
  if (!env.APP_PIN) return { ok: true, locked: false };
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const lockKey = 'lock:' + ip;

  const locked = await env.DATA_KV.get(lockKey);
  if (locked) return { ok: false, locked: true };

  const pin = request.headers.get('x-app-pin') || '';
  if (pin === env.APP_PIN) {
    const failKey = 'fails:' + ip;
    const hasFailRecord = await env.DATA_KV.get(failKey);
    if (hasFailRecord) {
      await env.DATA_KV.delete(failKey).catch(() => {});
    }
    return { ok: true, locked: false };
  }

  const failKey = 'fails:' + ip;
  const current = parseInt((await env.DATA_KV.get(failKey)) || '0', 10) + 1;
  if (current >= 5) {
    await env.DATA_KV.put(lockKey, '1', { expirationTtl: 900 }); // 15 min de bloqueio
    await env.DATA_KV.delete(failKey).catch(() => {});
  } else {
    await env.DATA_KV.put(failKey, String(current), { expirationTtl: 900 });
  }
  return { ok: false, locked: false };
}

function unauthorized(locked) {
  return new Response(JSON.stringify({ error: locked ? 'locked' : 'unauthorized' }), {
    status: locked ? 429 : 401,
    headers: { 'Content-Type': 'application/json' }
  });
}

// ===== Web Push (RFC 8291 + VAPID), implementado com Web Crypto =====

async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

async function deriveWebPushKeys(ecdhSecret, authSecret, uaPublic, asPublic, salt) {
  const te = new TextEncoder();
  const info1 = concatBytes(te.encode('WebPush: info\0'), uaPublic, asPublic);
  const prkKey = await hmacSha256(authSecret, ecdhSecret);
  const ikm = (await hmacSha256(prkKey, concatBytes(info1, new Uint8Array([1])))).slice(0, 32);

  const prk = await hmacSha256(salt, ikm);
  const cek = (await hmacSha256(prk, concatBytes(te.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmacSha256(prk, concatBytes(te.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);
  return { cek, nonce };
}

function buildAes128gcmHeader(salt, recordSize, keyid) {
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, recordSize, false);
  return concatBytes(salt, rs, new Uint8Array([keyid.length]), keyid);
}

async function getVapidPrivateCryptoKey(env) {
  const pub = b64urlToBytes(env.VAPID_PUBLIC_KEY);
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  const d = b64urlToBytes(env.VAPID_PRIVATE_KEY);
  const jwk = { kty: 'EC', crv: 'P-256', d: bytesToB64url(d), x: bytesToB64url(x), y: bytesToB64url(y), ext: true };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function createVapidJWT(audience, subject, privateKey) {
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = { aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject };
  const te = new TextEncoder();
  const encHeader = bytesToB64url(te.encode(JSON.stringify(header)));
  const encPayload = bytesToB64url(te.encode(JSON.stringify(payload)));
  const unsigned = `${encHeader}.${encPayload}`;
  const sigBuf = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, te.encode(unsigned));
  return `${unsigned}.${bytesToB64url(new Uint8Array(sigBuf))}`;
}

async function sendWebPush(subscription, payloadObj, env) {
  const p256dh = b64urlToBytes(subscription.keys.p256dh);
  const authSecret = b64urlToBytes(subscription.keys.auth);

  const ephemeralKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey));

  const subscriberPublicKey = await crypto.subtle.importKey('raw', p256dh, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: subscriberPublicKey }, ephemeralKeyPair.privateKey, 256));

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { cek, nonce } = await deriveWebPushKeys(sharedSecret, authSecret, p256dh, asPublicRaw, salt);

  const plaintext = new TextEncoder().encode(JSON.stringify(payloadObj));
  const padded = concatBytes(plaintext, new Uint8Array([2]));
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cekKey, padded));

  const body = concatBytes(buildAes128gcmHeader(salt, 4096, asPublicRaw), ciphertext);

  const url = new URL(subscription.endpoint);
  const audience = `${url.protocol}//${url.host}`;
  const vapidPrivateKey = await getVapidPrivateCryptoKey(env);
  const jwt = await createVapidJWT(audience, 'mailto:admin@financas.app', vapidPrivateKey);

  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
      'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`
    },
    body
  });
}

async function subKeyFor(endpoint) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
  return 'sub:' + bytesToB64url(new Uint8Array(hash)).slice(0, 24);
}

async function sendToAllSubscriptions(env, payload) {
  const list = await env.DATA_KV.list({ prefix: 'sub:' });
  let sent = 0, removed = 0, failed = 0;
  const errors = [];
  for (const k of list.keys) {
    const raw = await env.DATA_KV.get(k.name);
    if (!raw) continue;
    let sub;
    try {
      sub = JSON.parse(raw);
    } catch (e) {
      await env.DATA_KV.delete(k.name).catch(() => {});
      removed++;
      continue;
    }
    try {
      const res = await sendWebPush(sub, payload, env);
      if (res.status === 404 || res.status === 410) {
        await env.DATA_KV.delete(k.name);
        removed++;
      } else if (res.ok) {
        sent++;
      } else {
        failed++;
        if (errors.length < 5) errors.push(`HTTP ${res.status}`);
      }
    } catch (e) {
      failed++;
      if (errors.length < 5) errors.push(String(e && e.message || e));
    }
  }
  return { sent, removed, failed, total: list.keys.length, errors };
}

// ===== Verificação diária (Cron) — aviso de orçamento mensal =====

async function checkBudgetAndNotify(env) {
  const settingsRaw = await env.DATA_KV.get('settings');
  const settings = settingsRaw ? JSON.parse(settingsRaw) : {};
  const threshold = settings.budgetThreshold;
  if (!threshold || threshold <= 0) return { sent: 0, reason: 'sem limite definido' };

  const dataRaw = await env.DATA_KV.get('transactions');
  const transactions = dataRaw ? JSON.parse(dataRaw) : [];

  const now = new Date();
  const monthKey = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
  const expenseTotal = transactions
    .filter(t => !t.deleted && t.type === 'expense' && typeof t.date === 'string' && t.date.slice(0, 7) === monthKey)
    .reduce((s, t) => s + (Number(t.amount) || 0), 0);

  if (expenseTotal <= threshold) return { sent: 0, reason: 'dentro do limite' };

  const guardKey = 'budget_alert_sent:' + monthKey;
  if (await env.DATA_KV.get(guardKey)) return { sent: 0, reason: 'já enviado este mês' };

  const payload = {
    title: 'Limite de despesas ultrapassado',
    body: `As despesas deste mês já somam ${expenseTotal.toFixed(2).replace('.', ',')} € (limite: ${threshold.toFixed(2).replace('.', ',')} €).`
  };
  const result = await sendToAllSubscriptions(env, payload);
  await env.DATA_KV.put(guardKey, '1', { expirationTtl: 40 * 86400 });
  return result;
}

// ===== Verificação diária (Cron) — lembretes de transações recorrentes =====

async function checkRecurringAndNotify(env) {
  const dataRaw = await env.DATA_KV.get('transactions');
  const transactions = dataRaw ? JSON.parse(dataRaw) : [];

  const now = new Date();
  const todayDay = now.getUTCDate();
  const monthKey = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;

  const recurringOnes = transactions.filter(t => !t.deleted && t.recurring && typeof t.date === 'string');
  const dueToday = [];

  for (const t of recurringOnes) {
    const day = parseInt(t.date.slice(8, 10), 10);
    if (todayDay !== day) continue;

    const alreadyLogged = transactions.some(o =>
      !o.deleted && typeof o.date === 'string' && o.date.slice(0, 7) === monthKey &&
      o.desc === t.desc && o.category === t.category
    );
    if (alreadyLogged) continue;

    const guardKey = `recur_sent:${t.id}:${monthKey}`;
    if (await env.DATA_KV.get(guardKey)) continue;

    dueToday.push(t);
    await env.DATA_KV.put(guardKey, '1', { expirationTtl: 40 * 86400 });
  }

  if (dueToday.length === 0) return { sent: 0, reason: 'nada devido hoje' };

  const names = dueToday.map(t => t.desc).slice(0, 5).join(', ');
  const payload = {
    title: `${dueToday.length} transação(ões) recorrente(s) hoje`,
    body: names
  };
  return sendToAllSubscriptions(env, payload);
}

// ===== Worker =====

const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "frame-ancestors 'none'"
};

function withSecurityHeaders(response) {
  const newResponse = new Response(response.body, response);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    newResponse.headers.set(k, v);
  }
  return newResponse;
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/api/transactions') {
    if (request.method === 'GET') {
      const auth = await checkPinWithLockout(request, env);
      if (!auth.ok) return unauthorized(auth.locked);
      const data = await env.DATA_KV.get('transactions');
      const version = (await env.DATA_KV.get('transactions_version')) || '0';
      return new Response(data || '[]', {
        headers: { 'Content-Type': 'application/json', 'X-Data-Version': version }
      });
    }
    if (request.method === 'POST') {
      const auth = await checkPinWithLockout(request, env);
      if (!auth.ok) return unauthorized(auth.locked);
      let body;
      try { body = await request.json(); } catch (e) {
        return new Response(JSON.stringify({ error: 'invalid json' }), { status: 400 });
      }
      if (!Array.isArray(body)) return new Response(JSON.stringify({ error: 'expected array' }), { status: 400 });

      const isValid = body.every(item =>
        item && typeof item === 'object' &&
        typeof item.desc === 'string' && item.desc.trim().length > 0 &&
        typeof item.amount === 'number' && item.amount > 0 &&
        (item.type === 'income' || item.type === 'expense') &&
        typeof item.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(item.date)
      );
      if (!isValid) {
        return new Response(JSON.stringify({ error: 'invalid transaction data' }), { status: 400 });
      }

      const clientVersion = request.headers.get('x-client-version') || '0';
      const serverVersion = (await env.DATA_KV.get('transactions_version')) || '0';
      if (clientVersion !== serverVersion) {
        return new Response(JSON.stringify({ error: 'conflict', serverVersion }), { status: 409 });
      }

      const newVersion = String(Date.now());
      await env.DATA_KV.put('transactions', JSON.stringify(body));
      await env.DATA_KV.put('transactions_version', newVersion);
      return new Response(JSON.stringify({ ok: true, version: newVersion }), { headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('Method not allowed', { status: 405 });
  }

  if (path === '/api/settings') {
    if (request.method === 'GET') {
      const auth = await checkPinWithLockout(request, env);
      if (!auth.ok) return unauthorized(auth.locked);
      const data = await env.DATA_KV.get('settings');
      return new Response(data || '{}', { headers: { 'Content-Type': 'application/json' } });
    }
    if (request.method === 'POST') {
      const auth = await checkPinWithLockout(request, env);
      if (!auth.ok) return unauthorized(auth.locked);
      let body;
      try { body = await request.json(); } catch (e) {
        return new Response(JSON.stringify({ error: 'invalid json' }), { status: 400 });
      }
      const budgetThreshold = (body && typeof body.budgetThreshold === 'number' && body.budgetThreshold > 0)
        ? body.budgetThreshold : null;
      await env.DATA_KV.put('settings', JSON.stringify({ budgetThreshold }));
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('Method not allowed', { status: 405 });
  }

  if (path === '/api/subscribe' && request.method === 'POST') {
    const auth = await checkPinWithLockout(request, env);
    if (!auth.ok) return unauthorized(auth.locked);
    let sub;
    try { sub = await request.json(); } catch (e) {
      return new Response(JSON.stringify({ error: 'invalid json' }), { status: 400 });
    }
    if (!sub || !sub.endpoint || !sub.keys) {
      return new Response(JSON.stringify({ error: 'invalid subscription' }), { status: 400 });
    }
    const key = await subKeyFor(sub.endpoint);
    await env.DATA_KV.put(key, JSON.stringify(sub));
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  if (path === '/api/test-push') {
    const auth = await checkPinWithLockout(request, env);
    if (!auth.ok) return unauthorized(auth.locked);
    const result = await sendToAllSubscriptions(env, {
      title: 'Teste — Finanças',
      body: 'Se estás a ver isto, as notificações estão a funcionar.'
    });
    return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    const response = await handleRequest(request, env);
    return withSecurityHeaders(response);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(Promise.all([checkBudgetAndNotify(env), checkRecurringAndNotify(env)]));
  }
};
