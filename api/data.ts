import type { IncomingMessage, ServerResponse } from 'node:http';
import { EdunextClient } from '../src/core/client.js';

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-school-domain, x-user-id');

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

  // If no token but userId is provided, attempt auto-login via Cloudflare D1
  if (!token && userId) {
    try {
      const d1Res = await fetch('https://redunxt-d1-service.anonymouspotato.workers.dev/accounts/auto-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId }),
      });
      const d1Data = (await d1Res.json()) as any;
      if (d1Data.success && d1Data.token) {
        token = d1Data.token;
      }
    } catch {}
  }

  if (!token) {
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
