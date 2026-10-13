import type { IncomingMessage, ServerResponse } from 'node:http';

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
    return;
  }

  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: false, error: 'Method not allowed' }));
    return;
  }

  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });

  req.on('end', async () => {
    try {
      const { userId, password, schoolDomain = 'dpsharni.edunext2.com' } = JSON.parse(body || '{}');

      if (!userId || !password) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ success: false, error: 'User ID and password are required.' }));
        return;
      }

      // Call Cloudflare D1 multi-account service to authenticate, fetch profile details, and persist
      const d1Res = await fetch('https://redunxt-d1-service.anonymouspotato.workers.dev/accounts/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, password, schoolDomain }),
      });

      const json = (await d1Res.json()) as any;

      if (!d1Res.ok || !json.success || !json.token) {
        res.statusCode = d1Res.status || 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            success: false,
            error: json.error || 'Invalid User ID or Password.',
          })
        );
        return;
      }

      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          success: true,
          token: json.token,
          deviceToken: json.deviceToken,
          account: json.account,
        })
      );
    } catch (err: any) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: false, error: err.message || 'Authentication error.' }));
    }
  });
}
