export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  if (request.method !== 'GET') {
    return json({ error: 'Method not allowed' }, 405);
  }

  try {
    const reqUrl = new URL(request.url);
    const rawInput = String(reqUrl.searchParams.get('url') || reqUrl.searchParams.get('playlistId') || '').trim();
    const playlistId = extractPlaylistId(rawInput);
    if (!playlistId) {
      return json({ error: 'Provide a valid YouTube playlist URL or playlistId.' }, 400);
    }

    const maxItems = clampNumber(reqUrl.searchParams.get('maxItems'), 1, 500, 300);
    const configuredApiKey = String(env?.YOUTUBE_API_KEY || env?.YOUTUBE_DATA_API_KEY || '').trim();

    if (configuredApiKey) {
      try {
        const apiResult = await fetchFromYouTubeDataApi(playlistId, configuredApiKey, maxItems);
        if (apiResult.items.length) {
          return json({
            playlistId,
            playlistTitle: apiResult.playlistTitle || '',
            items: apiResult.items,
            source: 'youtube-data-api'
          });
        }
      } catch (_) {
        // Fall through to scraping fallback.
      }
    }

    try {
      const scraped = await fetchFromPlaylistPage(playlistId, maxItems);
      if (scraped.items.length) {
        return json({
          playlistId,
          playlistTitle: scraped.playlistTitle || '',
          items: scraped.items,
          source: 'youtube-page-scrape'
        });
      }
    } catch (_) {
      // Fall through to feed fallback.
    }

    const feedResult = await fetchFromPlaylistFeed(playlistId, maxItems);
    if (!feedResult.items.length) {
      return json({ error: 'No playable videos were found in this playlist.' }, 422);
    }

    return json({
      playlistId,
      playlistTitle: feedResult.playlistTitle || '',
      items: feedResult.items,
      source: 'youtube-feed'
    });
  } catch (error) {
    return json({ error: error?.message || 'Failed to import playlist.' }, 500);
  }
}

async function fetchFromYouTubeDataApi(playlistId, apiKey, maxItems) {
  let nextPageToken = '';
  const items = [];
  let playlistTitle = '';

  while (items.length < maxItems) {
    const endpoint = new URL('https://www.googleapis.com/youtube/v3/playlistItems');
    endpoint.searchParams.set('part', 'snippet');
    endpoint.searchParams.set('playlistId', playlistId);
    endpoint.searchParams.set('maxResults', '50');
    endpoint.searchParams.set('key', apiKey);
    if (nextPageToken) endpoint.searchParams.set('pageToken', nextPageToken);

    const response = await fetch(endpoint.toString(), {
      headers: {
        'User-Agent': 'GCSEMatePlaylistImporter/1.0 (+https://gcsemate.com)'
      }
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload?.error?.message || `YouTube API error (${response.status})`);
    }

    const pageItems = Array.isArray(payload?.items) ? payload.items : [];
    pageItems.forEach((entry) => {
      if (items.length >= maxItems) return;
      const snippet = entry?.snippet || {};
      const videoId = String(snippet?.resourceId?.videoId || '').trim();
      if (!videoId) return;
      if (!playlistTitle) {
        playlistTitle = cleanText(snippet?.playlistTitle || '');
      }
      items.push(toPlaylistVideoItem(videoId, snippet?.title || '', items.length));
    });

    if (!payload?.nextPageToken) break;
    nextPageToken = String(payload.nextPageToken);
  }

  return { playlistTitle, items };
}

async function fetchFromPlaylistPage(playlistId, maxItems) {
  const playlistUrl = `https://www.youtube.com/playlist?list=${encodeURIComponent(playlistId)}&hl=en`;
  const response = await fetch(playlistUrl, {
    headers: {
      'User-Agent': 'GCSEMatePlaylistImporter/1.0 (+https://gcsemate.com)',
      Accept: 'text/html,application/xhtml+xml'
    }
  });

  if (!response.ok) {
    throw new Error(`YouTube playlist page request failed (${response.status})`);
  }

  const html = await response.text();
  const initialData = extractInitialDataFromHtml(html);
  if (!initialData) return { playlistTitle: '', items: [] };

  const playlistListRenderer = findFirstByKey(initialData, 'playlistVideoListRenderer');
  const baseContents = Array.isArray(playlistListRenderer?.contents) ? playlistListRenderer.contents : [];

  const seen = new Set();
  const items = [];
  let continuationToken = '';

  const baseResult = extractVideosAndContinuation(baseContents, seen, items, maxItems);
  continuationToken = baseResult.continuationToken || '';

  const innertubeKey = extractInnertubeApiKey(html);
  const innertubeContext = extractInnertubeContext(html);

  let guard = 0;
  while (continuationToken && innertubeKey && items.length < maxItems && guard < 20) {
    guard += 1;
    const continuationItems = await fetchContinuationItems(continuationToken, innertubeKey, innertubeContext);
    if (!continuationItems.length) break;

    const continuationResult = extractVideosAndContinuation(continuationItems, seen, items, maxItems);
    continuationToken = continuationResult.continuationToken || '';
  }

  return {
    playlistTitle: readText(initialData?.metadata?.playlistMetadataRenderer?.title) || '',
    items: items.slice(0, maxItems)
  };
}

async function fetchContinuationItems(token, apiKey, context) {
  const endpoint = `https://www.youtube.com/youtubei/v1/browse?key=${encodeURIComponent(apiKey)}`;
  const body = {
    context: context || {
      client: {
        clientName: 'WEB',
        clientVersion: '2.20250301.00.00',
        hl: 'en',
        gl: 'US'
      }
    },
    continuation: token
  };

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'User-Agent': 'GCSEMatePlaylistImporter/1.0 (+https://gcsemate.com)'
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) return [];
  const payload = await response.json().catch(() => null);
  if (!payload) return [];
  return extractContinuationItems(payload);
}

function extractContinuationItems(payload) {
  const actionBlocks = [
    ...(Array.isArray(payload?.onResponseReceivedActions) ? payload.onResponseReceivedActions : []),
    ...(Array.isArray(payload?.onResponseReceivedCommands) ? payload.onResponseReceivedCommands : []),
    ...(Array.isArray(payload?.onResponseReceivedEndpoints) ? payload.onResponseReceivedEndpoints : [])
  ];

  for (const block of actionBlocks) {
    const appended = block?.appendContinuationItemsAction?.continuationItems;
    if (Array.isArray(appended)) return appended;

    const reloaded = block?.reloadContinuationItemsCommand?.continuationItems;
    if (Array.isArray(reloaded)) return reloaded;
  }

  const direct = payload?.continuationContents?.playlistVideoListContinuation?.contents;
  if (Array.isArray(direct)) return direct;

  return [];
}

function extractVideosAndContinuation(contents, seen, collector, maxItems) {
  let continuationToken = '';

  (contents || []).forEach((entry) => {
    if (collector.length >= maxItems) return;

    const renderer = entry?.playlistVideoRenderer || entry?.playlistPanelVideoRenderer;
    if (renderer) {
      const videoId = String(renderer?.videoId || '').trim();
      if (videoId && !seen.has(videoId)) {
        seen.add(videoId);
        const title = readText(renderer?.title) || readText(renderer?.videoTitle) || 'YouTube video';
        collector.push(toPlaylistVideoItem(videoId, title, collector.length));
      }
    }

    const token =
      entry?.continuationItemRenderer?.continuationEndpoint?.continuationCommand?.token ||
      entry?.continuationItemRenderer?.button?.buttonRenderer?.command?.continuationCommand?.token ||
      '';
    if (token) continuationToken = String(token);
  });

  return { continuationToken };
}

async function fetchFromPlaylistFeed(playlistId, maxItems) {
  const feedUrl = `https://www.youtube.com/feeds/videos.xml?playlist_id=${encodeURIComponent(playlistId)}`;
  const response = await fetch(feedUrl, {
    headers: {
      'User-Agent': 'GCSEMatePlaylistImporter/1.0 (+https://gcsemate.com)',
      Accept: 'application/atom+xml,application/xml,text/xml'
    }
  });

  if (!response.ok) {
    throw new Error(`YouTube feed request failed (${response.status})`);
  }

  const xml = await response.text();
  const playlistTitle = decodeXmlEntities((xml.match(/<feed[\s\S]*?<title>([\s\S]*?)<\/title>/i) || [])[1] || '');
  const entryMatches = [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/gi)];
  const items = [];

  for (const match of entryMatches) {
    if (items.length >= maxItems) break;
    const entryXml = match[1] || '';
    const videoId = (entryXml.match(/<yt:videoId>([^<]+)<\/yt:videoId>/i) || [])[1] || '';
    if (!videoId) continue;
    const title = decodeXmlEntities((entryXml.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || 'YouTube video');
    items.push(toPlaylistVideoItem(videoId, title, items.length));
  }

  return { playlistTitle, items };
}

function toPlaylistVideoItem(videoId, title, order) {
  const cleanVideoId = String(videoId || '').trim();
  const cleanTitle = cleanText(title || 'YouTube video');
  return {
    videoId: cleanVideoId,
    title: cleanTitle,
    order,
    watchUrl: `https://www.youtube.com/watch?v=${encodeURIComponent(cleanVideoId)}`,
    embedUrl: `https://www.youtube.com/embed/${encodeURIComponent(cleanVideoId)}?modestbranding=1&rel=0&playsinline=1`
  };
}

function readText(node) {
  if (!node) return '';
  if (typeof node === 'string') return cleanText(node);
  if (typeof node.simpleText === 'string') return cleanText(node.simpleText);
  if (Array.isArray(node.runs)) {
    return cleanText(node.runs.map((run) => run?.text || '').join(' '));
  }
  return '';
}

function findFirstByKey(root, key) {
  if (!root || typeof root !== 'object') return null;
  if (Object.prototype.hasOwnProperty.call(root, key)) {
    return root[key];
  }

  if (Array.isArray(root)) {
    for (const item of root) {
      const found = findFirstByKey(item, key);
      if (found) return found;
    }
    return null;
  }

  for (const value of Object.values(root)) {
    const found = findFirstByKey(value, key);
    if (found) return found;
  }
  return null;
}

function extractInitialDataFromHtml(html) {
  const markers = ['var ytInitialData = ', 'ytInitialData = ', 'window["ytInitialData"] = '];
  for (const marker of markers) {
    const data = extractJsonObjectAfterMarker(html, marker);
    if (data) return data;
  }
  return null;
}

function extractInnertubeApiKey(html) {
  const match = html.match(/"INNERTUBE_API_KEY"\s*:\s*"([^"]+)"/i);
  return match ? String(match[1]).trim() : '';
}

function extractInnertubeContext(html) {
  const ytcfg = extractJsonObjectAfterMarker(html, 'ytcfg.set(');
  if (ytcfg?.INNERTUBE_CONTEXT) {
    return ytcfg.INNERTUBE_CONTEXT;
  }
  return {
    client: {
      clientName: 'WEB',
      clientVersion: '2.20250301.00.00',
      hl: 'en',
      gl: 'US'
    }
  };
}

function extractJsonObjectAfterMarker(source, marker) {
  const markerIndex = source.indexOf(marker);
  if (markerIndex < 0) return null;

  const objectStart = source.indexOf('{', markerIndex + marker.length);
  if (objectStart < 0) return null;

  return parseJsonObjectAt(source, objectStart);
}

function parseJsonObjectAt(source, startIndex) {
  let depth = 0;
  let inString = false;
  let escaping = false;

  for (let i = startIndex; i < source.length; i += 1) {
    const ch = source[i];

    if (inString) {
      if (escaping) {
        escaping = false;
      } else if (ch === '\\') {
        escaping = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      continue;
    }

    if (ch === '{') depth += 1;
    if (ch === '}') depth -= 1;

    if (depth === 0) {
      const jsonText = source.slice(startIndex, i + 1);
      try {
        return JSON.parse(jsonText);
      } catch (_) {
        return null;
      }
    }
  }

  return null;
}

function extractPlaylistId(rawInput) {
  const input = String(rawInput || '').trim();
  if (!input) return '';

  if (/^[A-Za-z0-9_-]{10,}$/.test(input) && !input.includes('/')) {
    return cleanPlaylistId(input);
  }

  try {
    const normalized = /^https?:\/\//i.test(input) ? input : `https://${input}`;
    const parsed = new URL(normalized);
    const listParam = parsed.searchParams.get('list');
    if (listParam) return cleanPlaylistId(listParam);
  } catch (_) {
    // Continue with regex fallback.
  }

  const match = input.match(/(?:list=|playlist\/)([A-Za-z0-9_-]{10,})/i);
  return cleanPlaylistId(match?.[1] || '');
}

function cleanPlaylistId(value) {
  return String(value || '').split('&')[0].split('?')[0].trim();
}

function clampNumber(rawValue, min, max, fallbackValue) {
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed)) return fallbackValue;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function cleanText(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim();
}

function decodeXmlEntities(value) {
  return String(value || '')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
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
