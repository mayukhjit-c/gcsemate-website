// Minimal serverless handler to verify reCAPTCHA Enterprise tokens
// Env vars required:
// - RECAPTCHA_SECRET_KEY: Secret key for standard reCAPTCHA v3

async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.setHeader('Allow', 'POST');
      return res.end(JSON.stringify({ error: 'Method not allowed' }));
    }

    const secret = process.env.RECAPTCHA_SECRET_KEY;

    if (!secret) {
      res.statusCode = 500;
      return res.end(JSON.stringify({ error: 'Server not configured for reCAPTCHA verification' }));
    }

    let body = '';
    await new Promise((resolve) => {
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', resolve);
    });
    let parsed;
    try { parsed = JSON.parse(body || '{}'); } catch (_) { parsed = {}; }

    const token = parsed.token;
    const expectedAction = parsed.expectedAction || 'LOGIN';

    if (!token) {
      res.statusCode = 400;
      return res.end(JSON.stringify({ error: 'Missing token' }));
    }

    const params = new URLSearchParams();
    params.set('secret', secret);
    params.set('response', token);

    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    const data = await response.json();

    if (!response.ok) {
      res.statusCode = response.status;
      return res.end(JSON.stringify({ error: 'Verification request failed', details: data }));
    }

    const success = data.success === true;
    const actionMatches = !data.action || data.action === expectedAction;
    const score = typeof data.score === 'number' ? data.score : 0;
    const threshold = 0.3;
    const allowed = success && actionMatches && score >= threshold;

    res.statusCode = allowed ? 200 : 403;
    return res.end(JSON.stringify({ allowed, score, hostname: data.hostname, challenge_ts: data.challenge_ts }));
  } catch (error) {
    res.statusCode = 500;
    return res.end(JSON.stringify({ error: 'Server error', message: error.message }));
  }
}

export default handler;
module.exports = handler;
