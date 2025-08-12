export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });
  if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);

  try {
    const url = new URL(request.url);
    const root = url.searchParams.get('root');
    if (!root) return json({ error: "Missing 'root' query param" }, 400);

    const driveUrl = new URL('https://www.googleapis.com/drive/v3/files');
    driveUrl.searchParams.set('q', `'${root}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`);
    driveUrl.searchParams.set('fields', 'files(id,name)');
    driveUrl.searchParams.set('pageSize', '1000');
    driveUrl.searchParams.set('key', env.GDRIVE_API_KEY);

    const res = await fetch(driveUrl.toString());
    const data = await res.json();
    if (!res.ok) return json({ error: data.error?.message || 'Drive error' }, res.status);
    return json({ files: data.files || [] });
  } catch (e) {
    return json({ error: e.message || 'Server error' }, 500);
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...corsHeaders() },
  });
}
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,OPTIONS',
    'Access-Control-Allow-Headers': 'content-type',
  };
}
