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
    const targetUrl = String(reqUrl.searchParams.get('url') || '').trim();

    if (!targetUrl) {
      return json({ error: "Missing 'url' query parameter" }, 400);
    }

    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (_) {
      return json({ error: 'Invalid URL' }, 400);
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return json({ error: 'Only http(s) URLs are allowed' }, 400);
    }

    const response = await fetch(parsed.toString(), {
      headers: {
        'User-Agent': 'GCSEMateLessonScraper/1.0 (+https://gcsemate.com)',
        Accept: 'text/html,application/xhtml+xml'
      }
    });

    if (!response.ok) {
      return json({ error: `Upstream request failed (${response.status})` }, 502);
    }

    const html = await response.text();
    const title =
      decodeHtmlEntity(findTagContent(html, 'title')) ||
      decodeHtmlEntity(findMetaContent(html, 'og:title')) ||
      decodeHtmlEntity(findMetaContent(html, 'twitter:title')) ||
      parsed.hostname;

    const summary =
      decodeHtmlEntity(findMetaNameContent(html, 'description')) ||
      decodeHtmlEntity(findMetaContent(html, 'og:description')) ||
      '';

    const imageCandidates = [
      findMetaContent(html, 'og:image'),
      findMetaContent(html, 'twitter:image')
    ].filter(Boolean);

    const bodyTextBlocks = extractBodyTextBlocks(html);
    const imageUrls = [...new Set([...imageCandidates, ...extractImageSources(html)].map((src) => toAbsoluteUrl(src, parsed)).filter(Boolean))]
      .slice(0, 20);

    const contentHtml = buildContentHtml(title, summary, bodyTextBlocks, parsed.toString());

    return json({
      title,
      summary,
      imageUrls,
      contentHtml
    });
  } catch (error) {
    return json({ error: error?.message || 'Failed to scrape URL' }, 500);
  }
}

function findTagContent(html, tagName) {
  const regex = new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)<\\/${tagName}>`, 'i');
  const match = html.match(regex);
  return match ? cleanInlineText(match[1]) : '';
}

function findMetaContent(html, propertyName) {
  const regex = new RegExp(`<meta[^>]+property=["']${escapeRegex(propertyName)}["'][^>]*content=["']([^"']+)["'][^>]*>`, 'i');
  const reverseRegex = new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]*property=["']${escapeRegex(propertyName)}["'][^>]*>`, 'i');
  const match = html.match(regex) || html.match(reverseRegex);
  return match ? cleanInlineText(match[1]) : '';
}

function findMetaNameContent(html, name) {
  const regex = new RegExp(`<meta[^>]+name=["']${escapeRegex(name)}["'][^>]*content=["']([^"']+)["'][^>]*>`, 'i');
  const reverseRegex = new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]*name=["']${escapeRegex(name)}["'][^>]*>`, 'i');
  const match = html.match(regex) || html.match(reverseRegex);
  return match ? cleanInlineText(match[1]) : '';
}

function extractBodyTextBlocks(html) {
  const stripped = html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--([\s\S]*?)-->/g, ' ');

  const headingMatches = [...stripped.matchAll(/<h[1-3][^>]*>([\s\S]*?)<\/h[1-3]>/gi)]
    .map((match) => cleanInlineText(match[1]))
    .filter(Boolean)
    .slice(0, 4);

  const paragraphMatches = [...stripped.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi)]
    .map((match) => cleanInlineText(match[1]))
    .filter((text) => text.length > 45)
    .slice(0, 8);

  return [...headingMatches, ...paragraphMatches].slice(0, 10);
}

function extractImageSources(html) {
  const matches = [...html.matchAll(/<img[^>]+src=["']([^"']+)["'][^>]*>/gi)];
  return matches
    .map((match) => cleanInlineText(match[1]))
    .filter(Boolean);
}

function buildContentHtml(title, summary, blocks, sourceUrl) {
  const safeBlocks = (blocks || []).map((block) => sanitizeHtml(block)).filter(Boolean);
  const safeTitle = sanitizeHtml(title || 'Imported content');
  const safeSummary = sanitizeHtml(summary || '');
  const safeSource = sanitizeHtml(sourceUrl || '');

  let html = `<h2>${safeTitle}</h2>`;
  if (safeSummary) {
    html += `<p>${safeSummary}</p>`;
  }

  safeBlocks.forEach((block) => {
    html += `<p>${block}</p>`;
  });

  html += `<p><strong>Source:</strong> <a href="${safeSource}" target="_blank" rel="noopener noreferrer">${safeSource}</a></p>`;
  return html;
}

function toAbsoluteUrl(value, baseUrl) {
  const raw = String(value || '').trim();
  if (!raw || raw.startsWith('data:') || raw.startsWith('javascript:')) return '';
  try {
    return new URL(raw, baseUrl).toString();
  } catch (_) {
    return '';
  }
}

function cleanInlineText(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim();
}

function decodeHtmlEntity(value) {
  return String(value || '')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
}

function sanitizeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
