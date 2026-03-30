export async function onRequest(context) {
  const { request } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  if (request.method !== 'GET') {
    return json({ error: 'Method not allowed' }, 405);
  }

  try {
    const reqUrl = new URL(request.url);
    const rawUrl = String(reqUrl.searchParams.get('url') || '').trim();
    if (!rawUrl) return json({ error: "Missing 'url' query parameter" }, 400);

    let target;
    try {
      target = new URL(rawUrl);
    } catch (_) {
      return json({ error: 'Invalid URL' }, 400);
    }

    if (!['http:', 'https:'].includes(target.protocol)) {
      return json({ error: 'Only http(s) URLs are allowed' }, 400);
    }

    const resp = await fetch(target.toString(), {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': 'GCSEMateVideoResolver/1.0 (+https://gcsemate.com)',
        Accept: 'text/html,application/xhtml+xml,*/*;q=0.8'
      }
    });

    const finalUrl = String(resp.url || target.toString());
    const youtube = parseYoutubeUrl(finalUrl);
    return json({
      sourceUrl: target.toString(),
      finalUrl,
      status: resp.status,
      youtube
    });
  } catch (error) {
    return json({ error: error?.message || 'Failed to resolve URL' }, 500);
  }
}

function parseYoutubeUrl(url) {
  try {
    const urlObj = new URL(url);
    const host = (urlObj.hostname || '').toLowerCase();
    const isYouTubeHost = host.includes('youtube.com') || host.includes('youtu.be') || host.includes('youtube-nocookie.com');
    if (!isYouTubeHost) return null;

    const playlistId = urlObj.searchParams.get('list');
    if (playlistId) {
      const cleanPlaylistId = playlistId.split('&')[0].split('?')[0];
      return {
        type: 'youtube_playlist',
        id: cleanPlaylistId,
        embedUrl: `https://www.youtube.com/embed/videoseries?list=${cleanPlaylistId}&modestbranding=1&rel=0&playsinline=1`,
        watchUrl: `https://www.youtube.com/playlist?list=${cleanPlaylistId}`
      };
    }

    let videoId = urlObj.searchParams.get('v');
    if (!videoId && host.includes('youtu.be')) {
      videoId = (urlObj.pathname || '').slice(1).split('?')[0].split('&')[0];
    }
    if (!videoId) {
      const parts = (urlObj.pathname || '').split('/').filter(Boolean);
      if (parts[0] === 'embed' && parts[1] && parts[1] !== 'videoseries') videoId = parts[1];
      else if ((parts[0] === 'shorts' || parts[0] === 'live') && parts[1]) videoId = parts[1];
    }

    if (!videoId) return null;
    const cleanVideoId = videoId.split('&')[0].split('?')[0];
    return {
      type: 'youtube_video',
      id: cleanVideoId,
      embedUrl: `https://www.youtube.com/embed/${cleanVideoId}?modestbranding=1&rel=0&playsinline=1`,
      watchUrl: `https://www.youtube.com/watch?v=${cleanVideoId}`
    };
  } catch (_) {
    return null;
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      ...corsHeaders()
    }
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,OPTIONS',
    'Access-Control-Allow-Headers': 'content-type'
  };
}
