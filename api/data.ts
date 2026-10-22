import type { IncomingMessage, ServerResponse } from 'node:http';
import { EdunextClient } from '../src/core/client.js';

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-school-domain, x-user-id, x-device-token');

  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
    return;
  }

  // Extract Bearer token from Authorization header
  const authHeader = req.headers.authorization || '';
  let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
  const schoolDomain = (req.headers['x-school-domain'] as string) || 'dpsharni.edunext2.com';
  const userId = req.headers['x-user-id'] as string;
  const deviceToken = req.headers['x-device-token'] as string;

  // Check if token is missing or expired
  let isExpired = false;
  if (token) {
    try {
      const parts = token.split('.');
      if (parts.length >= 2) {
        let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf-8'));
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
          isExpired = true;
        }
      }
    } catch {
      // Don't mark as expired if parse fails; let Edunext client attempt call
    }
  }

  // If no token or expired, attempt auto-refresh via Cloudflare D1
  if ((!token || isExpired) && userId && deviceToken) {
    try {
      const d1Res = await fetch('https://redunxt-d1-service.anonymouspotato.workers.dev/accounts/auto-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, deviceToken }),
      });
      const d1Data = (await d1Res.json()) as any;
      if (d1Data.success && d1Data.token) {
        token = d1Data.token;
        isExpired = false;
      }
    } catch {}
  }

  if (!token || isExpired) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        success: false,
        error: 'Please log in to view your dashboard.',
      })
    );
    return;
  }

  try {
    const client = new EdunextClient(schoolDomain, token);
    const bundle = await client.getCompleteStudentBundle();

    // Guard against silent 401s where all modules return empty arrays and no profile
    if ((!bundle.circulars || bundle.circulars.length === 0) && (!bundle.mailbox || bundle.mailbox.length === 0) && !bundle.profile) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          success: false,
          error: 'Session expired at school server. Please re-authenticate.',
        })
      );
      return;
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.end(
      JSON.stringify({
        success: true,
        ...bundle,
      })
    );
  } catch (err: any) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        success: false,
        error: err.message || 'Failed to fetch student data.',
      })
    );
  }
}
