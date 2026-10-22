// Redunxt Cloudflare Edge Worker with D1 Persistence, Multi-Account Session Isolation, and RFC 8291 Web Push Engine

function b64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64UrlToBytes(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    arr[i] = raw.charCodeAt(i);
  }
  return arr;
}

async function getVapidAuthHeader(endpoint, vapidConfig) {
  const aud = new URL(endpoint).origin;
  const header = b64Url(new TextEncoder().encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64Url(new TextEncoder().encode(JSON.stringify({
    aud,
    exp: Math.floor(Date.now() / 1000) + 43200,
    sub: vapidConfig.subject || 'mailto:support@redunxt.org'
  })));
  const unsignedToken = header + '.' + claims;

  const key = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      x: vapidConfig.x,
      y: vapidConfig.y,
      d: vapidConfig.privateKey
    },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(unsignedToken)
  );

  const jwt = unsignedToken + '.' + b64Url(sig);
  return 'vapid t=' + jwt + ', k=' + vapidConfig.publicKey;
}

async function sendWebPush(subscription, payload, vapidConfig) {
  const authHeader = await getVapidAuthHeader(subscription.endpoint, vapidConfig);

  const clientPubRaw = b64UrlToBytes(subscription.p256dh);
  const clientAuthRaw = b64UrlToBytes(subscription.auth);

  const serverKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const serverPubRaw = await crypto.subtle.exportKey('raw', serverKeyPair.publicKey);

  const clientPubKey = await crypto.subtle.importKey(
    'raw',
    clientPubRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: clientPubKey },
    serverKeyPair.privateKey,
    256
  );

  const infoHeader = new TextEncoder().encode('WebPush: info\0');
  const keyInfo = new Uint8Array(infoHeader.length + clientPubRaw.byteLength + serverPubRaw.byteLength);
  keyInfo.set(infoHeader, 0);
  keyInfo.set(clientPubRaw, infoHeader.length);
  keyInfo.set(new Uint8Array(serverPubRaw), infoHeader.length + clientPubRaw.byteLength);

  const prkKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const ikm = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: clientAuthRaw, info: keyInfo },
    prkKey,
    256
  );

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const saltKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const cekInfo = new TextEncoder().encode('Content-Encoding: aes128gcm\0');
  const cek = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: cekInfo },
    saltKey,
    { name: 'AES-GCM', length: 128 },
    false,
    ['encrypt']
  );

  const nonceInfo = new TextEncoder().encode('Content-Encoding: nonce\0');
  const nonce = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: nonceInfo },
    saltKey,
    96
  );

  const payloadText = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadText);
  const padded = new Uint8Array(payloadBytes.length + 1);
  padded.set(payloadBytes, 0);
  padded[payloadBytes.length] = 2;

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    cek,
    padded
  );

  const recordSize = new Uint8Array([0, 0, 16, 0]); // 4096
  const keyIdLen = new Uint8Array([65]);
  const body = new Uint8Array(16 + 4 + 1 + 65 + ciphertext.byteLength);
  let offset = 0;
  body.set(salt, offset); offset += 16;
  body.set(recordSize, offset); offset += 4;
  body.set(keyIdLen, offset); offset += 1;
  body.set(new Uint8Array(serverPubRaw), offset); offset += 65;
  body.set(new Uint8Array(ciphertext), offset);

  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': authHeader,
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
      'Urgency': 'normal'
    },
    body
  });
}

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '';
    const isAllowedOrigin = !origin || 
      origin.includes('vercel.app') || 
      origin.includes('localhost') || 
      origin.includes('127.0.0.1');

    const corsHeaders = {
      'Access-Control-Allow-Origin': isAllowedOrigin ? (origin || '*') : 'https://redunxt.vercel.app',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-school-domain, x-user-id, x-device-token',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // 1. Health check
    if (url.pathname === '/ping') {
      return new Response(JSON.stringify({ ok: true, status: 'active', secure: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // 2. POST /accounts/login - Validate with Edunext and register secure device session
    if (url.pathname === '/accounts/login' && request.method === 'POST') {
      try {
        const { userId, password, schoolDomain = 'dpsharni.edunext2.com' } = await request.json();
        const uId = String(userId || '').trim();
        const pass = String(password || '').trim();

        if (!uId || !pass) {
          return new Response(JSON.stringify({ success: false, error: 'User ID and password are required.' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const loginRes = await fetch('https://m1.edubac.com/rest/v4/student/openconnect', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'mvcdomainurl': schoolDomain,
            'Connection-type': '_write'
          },
          body: JSON.stringify({ userid: uId, password: pass })
        });
        const loginData = await loginRes.json();

        if (!loginData.success || !loginData.data?.openIdConnect) {
          return new Response(JSON.stringify({
            success: false,
            error: loginData.message || 'Invalid User ID or Password from Edunext.'
          }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const token = loginData.data.openIdConnect;

        let studentName = 'Student';
        let admissionNo = '';
        let classSection = '';
        let profilePhoto = '';

        try {
          const profRes = await fetch('https://m2.edubac.com/rest/v4/student/studentDetailsnew', {
            headers: {
              'Authorization': 'Bearer ' + token,
              'mvcdomainurl': schoolDomain,
              'Connection-type': '_read'
            }
          });
          const profData = await profRes.json();
          const p = profData.data?.studentMap;
          if (p) {
            studentName = p.studentname || studentName;
            admissionNo = p.enrollmentNo || admissionNo;
            classSection = p.className ? (p.className + (p.sectionName ? '-' + p.sectionName : '')) : '';
            profilePhoto = p.studentImage || '';
          }
        } catch {}

        let tokenExpiry = 0;
        try {
          const parts = token.split('.');
          const payload = JSON.parse(atob(parts[1]));
          tokenExpiry = payload.exp || 0;
        } catch {}

        await env.DB.prepare("INSERT INTO accounts (user_id, password, school_domain, student_name, admission_no, class_section, profile_photo, cached_token, token_expires_at, last_synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET password = excluded.password, school_domain = excluded.school_domain, student_name = excluded.student_name, admission_no = excluded.admission_no, class_section = excluded.class_section, profile_photo = excluded.profile_photo, cached_token = excluded.cached_token, token_expires_at = excluded.token_expires_at, last_synced_at = excluded.last_synced_at, updated_at = CURRENT_TIMESTAMP").bind(
          uId,
          pass,
          schoolDomain,
          studentName,
          admissionNo,
          classSection,
          profilePhoto,
          token,
          tokenExpiry
        ).run();

        const deviceToken = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
        const userAgent = request.headers.get('User-Agent') || 'browser';

        await env.DB.prepare("INSERT INTO device_sessions (user_id, device_token, user_agent, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)").bind(uId, deviceToken, userAgent).run();

        const existing = await env.DB.prepare(
          'SELECT avatar_mode, custom_avatar_url FROM accounts WHERE user_id = ?'
        ).bind(uId).first();

        return new Response(JSON.stringify({
          success: true,
          token,
          deviceToken,
          account: {
            userId: uId,
            studentName,
            admissionNo,
            classSection,
            profilePhoto,
            avatarMode: existing?.avatar_mode || 'edunext',
            customAvatarUrl: existing?.custom_avatar_url || null,
            schoolDomain
          }
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 3. POST /accounts/auto-login - Silent background token refresh for THIS authorized device only
    if (url.pathname === '/accounts/auto-login' && request.method === 'POST') {
      try {
        const { userId, deviceToken } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (!uId) {
          return new Response(JSON.stringify({ success: false, error: 'User ID is required.' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        if (!dToken) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Missing device authorization token. Please log in with credentials.'
          }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const validSession = await env.DB.prepare(
          'SELECT id FROM device_sessions WHERE user_id = ? AND device_token = ?'
        ).bind(uId, dToken).first();

        if (!validSession) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Unauthorized or expired device session. Please enter credentials to sign in.'
          }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const account = await env.DB.prepare(
          'SELECT * FROM accounts WHERE user_id = ?'
        ).bind(uId).first();

        if (!account) {
          return new Response(JSON.stringify({ success: false, error: 'No stored credentials found. Please sign in again.' }), {
            status: 404,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        let token = account.cached_token;
        const now = Math.floor(Date.now() / 1000);
        const isExpired = !account.token_expires_at || account.token_expires_at - 300 < now;

        if (isExpired || !token) {
          const loginRes = await fetch('https://m1.edubac.com/rest/v4/student/openconnect', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'mvcdomainurl': account.school_domain || 'dpsharni.edunext2.com',
              'Connection-type': '_write'
            },
            body: JSON.stringify({ userid: account.user_id, password: account.password })
          });
          const loginData = await loginRes.json();

          if (!loginData.success || !loginData.data?.openIdConnect) {
            return new Response(JSON.stringify({
              success: false,
              error: 'Session refresh failed: ' + (loginData.message || 'Password may have changed.')
            }), {
              status: 401,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
          }
          token = loginData.data.openIdConnect;

          let newExp = 0;
          try {
            const parts = token.split('.');
            newExp = JSON.parse(atob(parts[1])).exp || 0;
          } catch {}

          await env.DB.prepare(
            'UPDATE accounts SET cached_token = ?, token_expires_at = ?, last_synced_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
          ).bind(token, newExp, account.user_id).run();
        }

        let studentName = account.student_name || 'Student';
        let admissionNo = account.admission_no || '';
        let classSection = account.class_section || '';
        let profilePhoto = account.profile_photo || '';

        // If profile columns are empty or default, self-heal immediately from Edunext API
        if (!admissionNo || studentName === 'Student' || !classSection) {
          try {
            const profRes = await fetch('https://m2.edubac.com/rest/v4/student/studentDetailsnew', {
              headers: {
                'Authorization': 'Bearer ' + token,
                'mvcdomainurl': account.school_domain || 'dpsharni.edunext2.com',
                'Connection-type': '_read'
              }
            });
            const profData = await profRes.json();
            const p = profData.data?.studentMap;
            if (p) {
              studentName = p.studentname || studentName;
              admissionNo = p.enrollmentNo || admissionNo;
              classSection = p.className ? (p.className + (p.sectionName ? '-' + p.sectionName : '')) : '';
              profilePhoto = p.studentImage || profilePhoto;

              await env.DB.prepare(
                'UPDATE accounts SET student_name = ?, admission_no = ?, class_section = ?, profile_photo = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
              ).bind(studentName, admissionNo, classSection, profilePhoto, account.user_id).run();
            }
          } catch {}
        }

        return new Response(JSON.stringify({
          success: true,
          token,
          account: {
            userId: account.user_id,
            studentName,
            admissionNo,
            classSection,
            profilePhoto,
            avatarMode: account.avatar_mode || 'edunext',
            customAvatarUrl: account.custom_avatar_url,
            schoolDomain: account.school_domain
          }
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 4. POST /accounts/logout - Invalidate THIS device session & attached push subscriptions in D1
    if (url.pathname === '/accounts/logout' && request.method === 'POST') {
      try {
        const { userId, deviceToken } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (uId && dToken) {
          await env.DB.prepare(
            'DELETE FROM device_sessions WHERE user_id = ? AND device_token = ?'
          ).bind(uId, dToken).run();

          // Revoke push subscriptions on this device immediately so no notifications leak
          await env.DB.prepare(
            'DELETE FROM push_subscriptions WHERE user_id = ? AND device_token = ?'
          ).bind(uId, dToken).run();
        }

        return new Response(JSON.stringify({ success: true, message: 'Device session and push subscription revoked.' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 5. POST /accounts/settings - Update profile picture preferences for THIS account
    if (url.pathname === '/accounts/settings' && request.method === 'POST') {
      try {
        const { userId, deviceToken, avatarMode, customAvatarUrl } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (!uId || !dToken) {
          return new Response(JSON.stringify({ success: false, error: 'Authentication required.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const validSession = await env.DB.prepare(
          'SELECT id FROM device_sessions WHERE user_id = ? AND device_token = ?'
        ).bind(uId, dToken).first();

        if (!validSession) {
          return new Response(JSON.stringify({ success: false, error: 'Unauthorized device.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        await env.DB.prepare(
          'UPDATE accounts SET avatar_mode = ?, custom_avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
        ).bind(avatarMode || 'edunext', customAvatarUrl || null, uId).run();

        return new Response(JSON.stringify({ success: true, message: 'Settings saved.' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 6. GET /accounts/push/vapid-public-key - Return active VAPID public key
    if (url.pathname === '/accounts/push/vapid-public-key' && request.method === 'GET') {
      try {
        const vapidRow = await env.DB.prepare("SELECT value FROM system_config WHERE key = 'vapid'").first();
        if (!vapidRow?.value) {
          return new Response(JSON.stringify({ success: false, error: 'VAPID not configured' }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
        const vapid = JSON.parse(vapidRow.value);
        return new Response(JSON.stringify({ success: true, publicKey: vapid.publicKey }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 7. POST /accounts/push/subscribe - Register device push subscription for THIS user
    if (url.pathname === '/accounts/push/subscribe' && request.method === 'POST') {
      try {
        const { userId, deviceToken, subscription } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (!uId || !dToken || !subscription?.endpoint || !subscription?.keys?.p256dh || !subscription?.keys?.auth) {
          return new Response(JSON.stringify({ success: false, error: 'Missing subscription details or device authentication.' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const validSession = await env.DB.prepare(
          'SELECT id FROM device_sessions WHERE user_id = ? AND device_token = ?'
        ).bind(uId, dToken).first();

        if (!validSession) {
          return new Response(JSON.stringify({ success: false, error: 'Unauthorized device session.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        // Upsert subscription: conflict on endpoint transfers ownership strictly to new user & device token
        await env.DB.prepare(
          "INSERT INTO push_subscriptions (user_id, device_token, endpoint, p256dh, auth, updated_at) VALUES (?, ?, ?, ?, ?, datetime('now')) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, device_token = excluded.device_token, p256dh = excluded.p256dh, auth = excluded.auth, updated_at = datetime('now')"
        ).bind(uId, dToken, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth).run();

        return new Response(JSON.stringify({ success: true, message: 'Push subscription registered.' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 8. POST /accounts/push/unsubscribe - Revoke device push subscription
    if (url.pathname === '/accounts/push/unsubscribe' && request.method === 'POST') {
      try {
        const { userId, deviceToken, endpoint } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (dToken) {
          await env.DB.prepare(
            'DELETE FROM push_subscriptions WHERE device_token = ?'
          ).bind(dToken).run();
        } else if (endpoint) {
          await env.DB.prepare(
            'DELETE FROM push_subscriptions WHERE endpoint = ?'
          ).bind(endpoint).run();
        }

        return new Response(JSON.stringify({ success: true, message: 'Push subscription removed.' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 9. POST /accounts/push/test - Send immediate test push to verify notifications on THIS device
    if (url.pathname === '/accounts/push/test' && request.method === 'POST') {
      try {
        const { userId, deviceToken } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (!uId || !dToken) {
          return new Response(JSON.stringify({ success: false, error: 'Authentication required.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const validSession = await env.DB.prepare(
          'SELECT id FROM device_sessions WHERE user_id = ? AND device_token = ?'
        ).bind(uId, dToken).first();

        if (!validSession) {
          return new Response(JSON.stringify({ success: false, error: 'Unauthorized device session.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const account = await env.DB.prepare(
          'SELECT student_name FROM accounts WHERE user_id = ?'
        ).bind(uId).first();

        const studentName = account?.student_name || 'Student';

        const sub = await env.DB.prepare(
          'SELECT * FROM push_subscriptions WHERE user_id = ? AND device_token = ?'
        ).bind(uId, dToken).first();

        if (!sub) {
          return new Response(JSON.stringify({ success: false, error: 'No active push subscription registered on this device.' }), {
            status: 404,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const vapidRow = await env.DB.prepare("SELECT value FROM system_config WHERE key = 'vapid'").first();
        if (!vapidRow?.value) {
          return new Response(JSON.stringify({ success: false, error: 'VAPID configuration not found.' }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
        const vapidConfig = JSON.parse(vapidRow.value);

        const pushPayload = {
          title: 'Redunxt Push Verified!',
          body: 'Hello ' + studentName + '! Push notifications are working perfectly on this device.',
          icon: '/favicon.svg',
          url: '/',
          tag: 'redunxt-test-' + Date.now()
        };

        const pushRes = await sendWebPush(sub, pushPayload, vapidConfig);
        const pushStatus = pushRes.status;

        // Clean up expired subscriptions
        if (pushStatus === 404 || pushStatus === 410) {
          await env.DB.prepare('DELETE FROM push_subscriptions WHERE id = ?').bind(sub.id).run();
          return new Response(JSON.stringify({ success: false, error: 'Push subscription expired or invalid at gateway (status ' + pushStatus + '). Please re-subscribe.' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        return new Response(JSON.stringify({
          success: true,
          message: 'Test notification dispatched successfully (gateway status: ' + pushStatus + ').'
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 10. GET/POST /data - Concurrently fetch all 9 modules directly from Edunext microservices
    if (url.pathname === '/data') {
      const authHeader = request.headers.get('Authorization') || '';
      let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
      const schoolDomain = request.headers.get('x-school-domain') || 'dpsharni.edunext2.com';

      if (!token) {
        return new Response(JSON.stringify({ success: false, error: 'Authorization token required.' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      const headers = {
        'Authorization': 'Bearer ' + token,
        'mvcdomainurl': schoolDomain,
        'Connection-type': '_read',
        'Content-Type': 'application/json'
      };

      try {
        let yearId = 21;
        let profileId = 691;
        let uId = request.headers.get('x-user-id') || '';
        let isExpired = false;
        try {
          const parts = token.split('.');
          const payload = JSON.parse(atob(parts[1]));
          if (payload.academicyearid) yearId = payload.academicyearid;
          if (payload.studentprofileid) profileId = payload.studentprofileid;
          if (!uId && (payload.sub || payload.username)) uId = String(payload.sub || payload.username);
          if (payload.exp && (payload.exp - 300) < Math.floor(Date.now() / 1000)) {
            isExpired = true;
          }
        } catch {
          isExpired = true;
        }

        // Auto-refresh token from Edunext if expired and we have account credentials in D1
        if (isExpired && uId && env.DB) {
          const acc = await env.DB.prepare('SELECT * FROM accounts WHERE user_id = ?').bind(uId).first();
          if (acc && acc.password) {
            const lRes = await fetch('https://m1.edubac.com/rest/v4/student/openconnect', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'mvcdomainurl': acc.school_domain || schoolDomain,
                'Connection-type': '_write'
              },
              body: JSON.stringify({ userid: acc.user_id, password: acc.password })
            }).catch(() => null);
            const lData = lRes ? await lRes.json().catch(() => ({})) : {};
            if (lData?.success && lData?.data?.openIdConnect) {
              token = lData.data.openIdConnect;
              isExpired = false;
              headers['Authorization'] = 'Bearer ' + token;
              let exp = 0;
              try { exp = JSON.parse(atob(token.split('.')[1])).exp || 0; } catch {}
              await env.DB.prepare('UPDATE accounts SET cached_token = ?, token_expires_at = ?, last_synced_at = CURRENT_TIMESTAMP WHERE user_id = ?').bind(token, exp, uId).run();
            }
          }
        }

        if (isExpired) {
          return new Response(JSON.stringify({ success: false, error: 'Authorization token expired. Please log in.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const attUrl = 'https://m2.edubac.com/rest/v4/student/getStudentAttendanceCalander?academicyearid=' + yearId + '&fromdate=2026-04-01&todate=2027-03-31&studentprofileid=' + profileId;
        const resUrl = 'https://m12.edubac.com/rest/v4/student/getResultAnalysis?acedemicYearId=' + yearId;

        const [
          circularsRes,
          mailboxRes,
          newsRes,
          profileRes,
          homeworkRes,
          resultsRes,
          syllabusRes,
          downloadsRes,
          attendanceRes
        ] = await Promise.all([
          fetch('https://m1.edubac.com/rest/v4/student/getcirculardata', { method: 'GET', headers }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/Studentinboxnew?limit=1', { method: 'GET', headers }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getstudentnews', { method: 'GET', headers }).catch(() => null),
          fetch('https://m2.edubac.com/rest/v4/student/studentDetailsnew', { method: 'GET', headers }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/studentHomework', { method: 'GET', headers }).catch(() => null),
          fetch(resUrl, { method: 'GET', headers }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/StudentSyllabus?limit=1&fts=', { method: 'GET', headers }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getEresourceApi?fts=&limit=1', { method: 'GET', headers }).catch(() => null),
          fetch(attUrl, { method: 'GET', headers }).catch(() => null)
        ]);

        const [circulars, mailbox, news, profile, homework, results, syllabus, downloads, attendance] = await Promise.all([
          circularsRes ? circularsRes.json().catch(() => ({})) : {},
          mailboxRes ? mailboxRes.json().catch(() => ({})) : {},
          newsRes ? newsRes.json().catch(() => ({})) : {},
          profileRes ? profileRes.json().catch(() => ({})) : {},
          homeworkRes ? homeworkRes.json().catch(() => ({})) : {},
          resultsRes ? resultsRes.json().catch(() => ({})) : {},
          syllabusRes ? syllabusRes.json().catch(() => ({})) : {},
          downloadsRes ? downloadsRes.json().catch(() => ({})) : {},
          attendanceRes ? attendanceRes.json().catch(() => ({})) : {}
        ]);

        // Safe extraction and normalization
        const rawResults = results?.data?.resultdata || results?.data?.results || results?.resultdata || (Array.isArray(results?.data) ? results?.data : (Array.isArray(results) ? results : []));
        const normalizedResults = Array.isArray(rawResults) ? rawResults.map(r => ({
          termId: r.termid || r.termId,
          reportName: r.reportname || r.reportName || "Report Card",
          reportname: r.reportname || r.reportName || "Report Card",
          publishDate: r.publishdate || r.publishDate || "",
          publishdate: r.publishdate || r.publishDate || "",
          academicYear: r.academicyearid || r.academicYear || "",
          reportUrl: r.report || r.reportUrl || "",
          report: r.report || r.reportUrl || "",
          fullReportUrl: (r.report || r.reportUrl || "").startsWith("http") ? (r.report || r.reportUrl) : ("https://" + schoolDomain + (r.report || r.reportUrl || ""))
        })) : [];

        const rawHwList = homework?.data?.assgmentData || homework?.data?.homework_list || homework?.data?.assignments || (Array.isArray(homework?.data) ? homework?.data : (Array.isArray(homework) ? homework : []));
        const rawSubjects = homework?.data?.subjectList || homework?.data?.subjects || [];
        const normalizedHomework = {
          assignments: Array.isArray(rawHwList) ? rawHwList.map(a => {
            let atts = [];
            if (a.attachment) {
              try {
                const obj = typeof a.attachment === "string" ? JSON.parse(a.attachment) : a.attachment;
                let imgArr = obj?.image_array;
                if (typeof imgArr === "string") imgArr = JSON.parse(imgArr);
                if (Array.isArray(imgArr)) atts = imgArr;
              } catch {}
            } else if (Array.isArray(a.attachments)) {
              atts = a.attachments;
            }
            return {
              id: a.assignmentid || a.id,
              title: a.assignmentname || a.title || "Assignment",
              subject: a.subjectname || a.subject || "General",
              description: a.description || "",
              assignedBy: a.assignBy || a.assignedBy || "Teacher",
              createdOn: a.cretedon || a.createdOn || "",
              deadlineDate: a.deadlineDate || a.deadlinedate || "",
              deadlineTime: a.deadlinetime || a.deadlineTime || "",
              submissionRequired: Boolean(a.submission_required || a.submissionRequired),
              type: a.assignmenttypesName || a.type || "Homework",
              attachments: atts
            };
          }) : [],
          subjects: Array.isArray(rawSubjects) ? rawSubjects : []
        };

        const attData = attendance?.data || attendance || {};
        const monthlyGraph = [];
        if (attData.monthlyAttendanceGraph && typeof attData.monthlyAttendanceGraph === "object") {
          for (const [month, percentage] of Object.entries(attData.monthlyAttendanceGraph)) {
            monthlyGraph.push({ month, percentage: Number(percentage) });
          }
        } else if (Array.isArray(attData.monthlyGraph)) {
          monthlyGraph.push(...attData.monthlyGraph);
        }

        const calendarList = [];
        if (attData.calanderattendancelist && typeof attData.calanderattendancelist === "object") {
          const statusMap = attData.attendanceLeaveStatus || {};
          for (const [monthKey, daysObj] of Object.entries(attData.calanderattendancelist)) {
            if (typeof daysObj === "object" && daysObj !== null) {
              for (const [dayNum, statusId] of Object.entries(daysObj)) {
                const paddedDay = String(dayNum).padStart(2, "0");
                const dateStr = monthKey + "-" + paddedDay;
                const meta = statusMap[String(statusId)];
                const statusName = meta?.name || (statusId === 1 ? "Present" : statusId === 2 ? "Absent" : "Leave");
                const color = meta?.colorCode || (statusId === 1 ? "#22c55e" : statusId === 2 ? "#ef4444" : "#f59e0b");
                calendarList.push({ date: dateStr, status: statusName, statusId: Number(statusId), color });
              }
            }
          }
        } else if (Array.isArray(attData.calendarList)) {
          calendarList.push(...attData.calendarList);
        }

        const normalizedAttendance = {
          overallPercentage: attData.overallAttenndaceCard || attData.overallPercentage || "0%",
          presentCard: attData.presentCard || { totalDays: 0, presentDays: 0, presentPercentage: "0%" },
          absentCard: attData.absentCard || { totalDays: 0, absentDays: 0, absentPercentage: "0%" },
          leaveCard: attData.leaveCard || { totalDays: 0, leaveDays: 0, leavePercentage: "0%" },
          calendarList,
          monthlyGraph
        };

        const normalizedCirculars = circulars?.data?.circular_list || circulars?.data?.circularlist || (Array.isArray(circulars?.data) ? circulars?.data : (Array.isArray(circulars) ? circulars : []));
        const normalizedMailbox = mailbox?.data?.mail_box_list || mailbox?.data?.list || (Array.isArray(mailbox?.data) ? mailbox?.data : (Array.isArray(mailbox) ? mailbox : []));
        const normalizedNews = news?.data?.news_list || news?.data?.schoolnewslist || (Array.isArray(news?.data) ? news?.data : (Array.isArray(news) ? news : []));
        const rawSyllabusList = syllabus?.data?.syllabusdata || syllabus?.data?.syllabus_list || syllabus?.data?.list || [];
        const normalizedSyllabus = Array.isArray(rawSyllabusList) ? rawSyllabusList.map(item => ({
          id: item.id,
          subject: item.subjectname || item.subject || 'All Subjects',
          fileName: item.fileName || item.filename || '',
          description: (item.description || '').replace(/<[^>]+>/g, '').trim(),
          fileUrl: item.single_clound_front_url || item.servingUrl || item.fileUrl || ''
        })) : [];

        const rawDownloadList = downloads?.data?.data_array || downloads?.data?.download_list || downloads?.data?.list || [];
        const normalizedDownloads = Array.isArray(rawDownloadList) ? rawDownloadList.map(item => {
          let fileName = item.fileName || '';
          let fileUrl = item.fileUrl || '';
          if (item.filepath) {
            try {
              const obj = typeof item.filepath === 'string' ? JSON.parse(item.filepath) : item.filepath;
              const img = obj?.image_array?.[0];
              if (img) {
                fileName = img.filename || '';
                fileUrl = img.cloud_front_serving_url || img.servingUrl || '';
              }
            } catch {}
          }
          return {
            id: item.id,
            title: item.title1 || item.title || 'Untitled Resource',
            category: item.category1 || item.category || 'General',
            date: item.date1 || item.date || '',
            createdBy: item.createdBy || '',
            description: item.description1 || item.description || '',
            fileName,
            fileUrl
          };
        }) : [];

        let normalizedProfile = null;
        if (profile?.data?.studentMap) {
          const sm = profile.data.studentMap;
          normalizedProfile = {
            studentName: sm.studentname || 'Student',
            admissionNo: sm.enrollmentNo || '',
            className: sm.className || '',
            sectionName: sm.sectionName || '',
            rollNo: sm.username || '',
            classTeacherName: sm.classTeacherName || '',
            studentType: sm.studenttypename || '',
            houseName: sm.houseName || '',
            studentImage: sm.studentImage || '',
            studentMobile: sm.studentmobileno || '',
            studentEmail: sm.studentemailid || '',
            studentAddress: sm.studentaddress || '',
            fatherName: sm.fatherName || '',
            motherName: sm.motherName || '',
            academicYear: profile.data?.currentacademicyearName || '2026-27'
          };

          if (uId && env.DB) {
            const classSec = sm.className ? (sm.className + (sm.sectionName ? '-' + sm.sectionName : '')) : '';
            env.DB.prepare(
              "UPDATE accounts SET student_name = ?, admission_no = ?, class_section = ?, profile_photo = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?"
            ).bind(
              normalizedProfile.studentName,
              normalizedProfile.admissionNo,
              classSec,
              normalizedProfile.studentImage,
              uId
            ).run().catch(() => {});
          }
        } else {
          normalizedProfile = profile?.data?.personalDetail || profile?.data?.studentDetails || profile?.data || null;
        }

        // Guard against silent 401s where all modules return empty arrays and no profile
        if ((!normalizedCirculars || normalizedCirculars.length === 0) && (!normalizedMailbox || normalizedMailbox.length === 0) && !normalizedProfile) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Session expired or rejected by school portal. Please re-authenticate.'
          }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        return new Response(JSON.stringify({
          success: true,
          circulars: normalizedCirculars,
          mailbox: normalizedMailbox,
          news: normalizedNews,
          profile: normalizedProfile,
          homework: normalizedHomework,
          results: normalizedResults,
          syllabus: normalizedSyllabus,
          downloads: normalizedDownloads,
          attendance: normalizedAttendance
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders });
  },

  // Background Cron handler: Checks for new circulars and mails per user and sends Web Push
  async scheduled(event, env, ctx) {
    const users = await env.DB.prepare('SELECT DISTINCT user_id FROM push_subscriptions').all();
    if (!users?.results || users.results.length === 0) return;

    const vapidRow = await env.DB.prepare("SELECT value FROM system_config WHERE key = 'vapid'").first();
    if (!vapidRow?.value) return;
    const vapidConfig = JSON.parse(vapidRow.value);

    for (const row of users.results) {
      const userId = row.user_id;
      ctx.waitUntil((async () => {
        try {
          const account = await env.DB.prepare('SELECT * FROM accounts WHERE user_id = ?').bind(userId).first();
          if (!account) return;

          let token = account.cached_token;
          const now = Math.floor(Date.now() / 1000);
          if (!token || !account.token_expires_at || account.token_expires_at - 300 < now) {
            const lRes = await fetch('https://m1.edubac.com/rest/v4/student/openconnect', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'mvcdomainurl': account.school_domain || 'dpsharni.edunext2.com',
                'Connection-type': '_write'
              },
              body: JSON.stringify({ userid: account.user_id, password: account.password })
            });
            const lData = await lRes.json();
            if (lData.success && lData.data?.openIdConnect) {
              token = lData.data.openIdConnect;
              let exp = 0;
              try { exp = JSON.parse(atob(token.split('.')[1])).exp || 0; } catch {}
              await env.DB.prepare('UPDATE accounts SET cached_token = ?, token_expires_at = ?, last_synced_at = CURRENT_TIMESTAMP WHERE user_id = ?').bind(token, exp, userId).run();
            } else {
              return;
            }
          }

          const headers = {
            'Authorization': 'Bearer ' + token,
            'mvcdomainurl': account.school_domain || 'dpsharni.edunext2.com',
            'Connection-type': '_read',
            'Content-Type': 'application/json'
          };

          const [circRes, mailRes] = await Promise.all([
            fetch('https://m1.edubac.com/rest/v4/student/getcirculardata', { method: 'GET', headers }).catch(() => null),
            fetch('https://m1.edubac.com/rest/v4/student/Studentinboxnew?limit=1', { method: 'GET', headers }).catch(() => null)
          ]);

          const circData = circRes ? await circRes.json().catch(() => ({})) : {};
          const mailData = mailRes ? await mailRes.json().catch(() => ({})) : {};

          const circulars = circData?.data?.circularlist || circData?.data?.circular_list || [];
          const mails = mailData?.data?.list || mailData?.data?.mail_box_list || [];

          const subs = await env.DB.prepare('SELECT * FROM push_subscriptions WHERE user_id = ?').bind(userId).all();
          if (!subs?.results) return;

          for (const sub of subs.results) {
            // Check for new circulars (supports multiple in one poll cycle)
            if (circulars.length > 0) {
              const newCircs = [];
              for (const c of circulars) {
                const cId = String(c.id || c.circularid || c.circular_id || '');
                if (!cId) continue;
                if (sub.last_circular_id && cId === String(sub.last_circular_id)) break;
                newCircs.push(c);
                if (newCircs.length >= 3) break;
              }

              if (newCircs.length > 0) {
                for (const c of newCircs.slice().reverse()) {
                  const cId = String(c.id || c.circularid || c.circular_id || '');
                  const circTitle = c.name || c.circularname || c.circular_name || 'New Circular';
                  const circDesc = (c.discription || c.description || c.summary || '').replace(/<[^>]+>/g, '').trim().slice(0, 120);

                  await sendWebPush(sub, {
                    title: 'Circular: ' + circTitle,
                    body: circDesc || 'A new school circular has been published.',
                    icon: '/icon-192.png',
                    badge: '/badge-96.png',
                    url: '/#circulars',
                    tag: 'circ-' + cId
                  }, vapidConfig).catch(() => null);
                }

                const latestCircId = String(circulars[0].id || circulars[0].circularid || circulars[0].circular_id || '');
                await env.DB.prepare('UPDATE push_subscriptions SET last_circular_id = ?, last_checked_at = CURRENT_TIMESTAMP WHERE id = ?').bind(latestCircId, sub.id).run();
              }
            }

            // Check for new mails (supports multiple new mails in one poll cycle)
            if (mails.length > 0) {
              const newMails = [];
              for (const m of mails) {
                const mId = String(m.id || m.mailid || m.mail_id || '');
                if (!mId) continue;
                if (sub.last_mail_id && mId === String(sub.last_mail_id)) break;
                newMails.push(m);
                if (newMails.length >= 3) break;
              }

              if (newMails.length > 0) {
                for (const m of newMails.slice().reverse()) {
                  const mId = String(m.id || m.mailid || m.mail_id || '');
                  const mailSubject = m.subject || 'New School Mail';
                  const sender = m.employeename || m.from || m.sender_name || 'School';

                  await sendWebPush(sub, {
                    title: 'Mail: ' + mailSubject,
                    body: 'From: ' + sender,
                    icon: '/icon-192.png',
                    badge: '/badge-96.png',
                    url: '/#mailbox',
                    tag: 'mail-' + mId
                  }, vapidConfig).catch(() => null);
                }

                const latestMailId = String(mails[0].id || mails[0].mailid || mails[0].mail_id || '');
                await env.DB.prepare('UPDATE push_subscriptions SET last_mail_id = ?, last_checked_at = CURRENT_TIMESTAMP WHERE id = ?').bind(latestMailId, sub.id).run();
              }
            }
          }
        } catch (err) {
          console.error('Scheduled notification error for user ' + userId, err);
        }
      })());
    }
  }
};
