// Simple proxy to fetch public Google Drive files by id and return with CORS headers
// Usage: /api/proxy-drive?id=FILE_ID

async function handler(req, res) {
  try {
    // CORS preflight support
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      return res.end();
    }

    if (req.method !== 'GET') {
      res.statusCode = 405;
      res.setHeader('Allow', 'GET, OPTIONS');
      return res.end(JSON.stringify({ error: 'Method not allowed' }));
    }

    const url = new URL(req.url, 'http://localhost');
    const id = url.searchParams.get('id');
    if (!id) {
      res.statusCode = 400;
      return res.end(JSON.stringify({ error: 'Missing id' }));
    }

    const upstream = `https://drive.google.com/uc?export=download&id=${encodeURIComponent(id)}`;
    const upstreamRes = await fetch(upstream, { method: 'GET' });

    if (!upstreamRes.ok) {
      res.statusCode = upstreamRes.status;
      const text = await upstreamRes.text().catch(() => '');
      return res.end(text || JSON.stringify({ error: 'Upstream error' }));
    }

    const ct = upstreamRes.headers.get('content-type') || 'application/octet-stream';
    const cd = upstreamRes.headers.get('content-disposition') || 'attachment';
    res.statusCode = 200;
    res.setHeader('Content-Type', ct);
    res.setHeader('Content-Disposition', cd);

    const buf = Buffer.from(await upstreamRes.arrayBuffer());
    return res.end(buf);
  } catch (e) {
    res.statusCode = 500;
    return res.end(JSON.stringify({ error: 'Proxy error', message: e.message }));
  }
}

export default handler;
module.exports = handler;


