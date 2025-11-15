// Cloudflare Function for AI Tutor - Groq API Integration
// Handles rate limiting (30 requests/minute) and token tracking (64k max per user)
//
// Required Environment Variables:
//   - GROQ_API_KEY: Your Groq API key from https://console.groq.com/
//
// Setup:
//   1. Get Groq API key from https://console.groq.com/
//   2. Add environment variable in Cloudflare Pages: Settings → Environment Variables → GROQ_API_KEY
//   3. Deploy - the function will automatically handle rate limiting and token tracking
//
// Note: Rate limiting and token tracking use in-memory storage (resets on function restart).
// This is acceptable for most use cases. See docs/AI_TUTOR_SETUP.md for details.

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type',
  };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405);
  }

  try {
    // Get Groq API key from environment
    const GROQ_API_KEY = env.GROQ_API_KEY;
    if (!GROQ_API_KEY) {
      return json({ error: 'Groq API key not configured' }, 500);
    }

    // Parse request body
    const body = await request.json();
    const { message, userId, conversationHistory = [] } = body;

    if (!message || !userId) {
      return json({ error: 'Missing required fields: message, userId' }, 400);
    }

    // Rate limiting: 30 requests per minute per user
    // Uses in-memory storage (resets on function restart)
    const rateLimitKey = `ai_tutor_rate_${userId}`;
    let rateLimitData = { count: 0, resetAt: Date.now() + 60000 };
    
    // Optional: If KV namespace is bound, use it for persistence
    if (env.AI_TUTOR_KV) {
      try {
        const stored = await env.AI_TUTOR_KV.get(rateLimitKey, { type: 'json' });
        if (stored) {
          rateLimitData = stored;
        }
      } catch (error) {
        console.error('Error reading rate limit from KV:', error);
        // Continue with default values if KV read fails
      }
    }
    
    if (rateLimitData.resetAt < Date.now()) {
      // Reset counter
      rateLimitData.count = 0;
      rateLimitData.resetAt = Date.now() + 60000;
    }

    if (rateLimitData.count >= 30) {
      const waitTime = Math.ceil((rateLimitData.resetAt - Date.now()) / 1000);
      return json({ 
        error: 'Rate limit exceeded', 
        message: `Please wait ${waitTime} seconds before making another request. Maximum 30 requests per minute.` 
      }, 429);
    }

    // Increment rate limit counter
    rateLimitData.count++;
    if (env.AI_TUTOR_KV) {
      try {
        await env.AI_TUTOR_KV.put(rateLimitKey, JSON.stringify(rateLimitData), { expirationTtl: 60 });
      } catch (error) {
        console.error('Error writing rate limit to KV:', error);
        // Continue even if KV write fails (graceful degradation)
      }
    }

    // Token tracking: Check user's token usage (max 64k tokens)
    // Uses in-memory storage (resets on function restart)
    const tokenUsageKey = `ai_tutor_tokens_${userId}`;
    let tokenUsage = { tokens: 0, resetAt: Date.now() + (24 * 60 * 60 * 1000) }; // Daily reset
    
    // Optional: If KV namespace is bound, use it for persistence
    if (env.AI_TUTOR_KV) {
      try {
        const stored = await env.AI_TUTOR_KV.get(tokenUsageKey, { type: 'json' });
        if (stored) {
          tokenUsage = stored;
        }
      } catch (error) {
        console.error('Error reading token usage from KV:', error);
        // Continue with default values if KV read fails
      }
    }
    
    if (tokenUsage.resetAt < Date.now()) {
      // Reset daily token count
      tokenUsage.tokens = 0;
      tokenUsage.resetAt = Date.now() + (24 * 60 * 60 * 1000);
    }

    const MAX_TOKENS = 64000;
    if (tokenUsage.tokens >= MAX_TOKENS) {
      return json({ 
        error: 'Token limit exceeded', 
        message: 'You have reached your daily token limit of 64,000 tokens. Please try again tomorrow.' 
      }, 429);
    }

    // System prompt
    const systemPrompt = `You are GCSEMate AI, an intelligent tutoring assistant created by Mayukhjit Chakraborty. Your purpose is to help students with GCSE academic topics and questions about GCSEMate.

Guidelines:
- Only respond to academic questions related to GCSE subjects (Mathematics, English, Sciences, History, Geography, etc.) or questions about GCSEMate platform features
- Be helpful, clear, and educational in your responses
- If asked about non-academic topics or inappropriate content, politely redirect to academic subjects or GCSEMate features
- Be safe, harmless, and appropriate at all times
- Provide accurate information and encourage good study habits
- Keep responses concise but comprehensive
- Use UK English spelling and terminology (as GCSEs are UK qualifications)`;

    // Build messages array for Groq API
    const messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory.slice(-10), // Keep last 10 messages for context
      { role: 'user', content: message }
    ];

    // Call Groq API
    const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.1-8b-instant',
        messages: messages,
        temperature: 0.7,
        max_tokens: 2048,
        stream: false
      })
    });

    if (!groqResponse.ok) {
      const errorData = await groqResponse.text();
      console.error('Groq API error:', errorData);
      return json({ 
        error: 'AI service error', 
        message: 'Unable to process your request. Please try again later.' 
      }, 500);
    }

    const groqData = await groqResponse.json();
    const aiResponse = groqData.choices[0]?.message?.content || 'I apologize, but I was unable to generate a response. Please try again.';
    const tokensUsed = groqData.usage?.total_tokens || 0;

    // Update token usage
    tokenUsage.tokens += tokensUsed;
    if (env.AI_TUTOR_KV) {
      try {
        await env.AI_TUTOR_KV.put(tokenUsageKey, JSON.stringify(tokenUsage), { expirationTtl: 86400 });
      } catch (error) {
        console.error('Error writing token usage to KV:', error);
        // Continue even if KV write fails (graceful degradation)
      }
    }

    // Return response
    return json({
      response: aiResponse,
      tokensUsed: tokensUsed,
      totalTokensUsed: tokenUsage.tokens,
      tokensRemaining: Math.max(0, MAX_TOKENS - tokenUsage.tokens)
    });

  } catch (error) {
    console.error('AI Tutor function error:', error);
    return json({ 
      error: 'Internal server error', 
      message: 'An unexpected error occurred. Please try again later.' 
    }, 500);
  }
}

