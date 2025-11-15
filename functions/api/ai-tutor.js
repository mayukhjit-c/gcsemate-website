// Cloudflare Function for AI Tutor - Request-Based System with Firebase Firestore
// Handles daily request limits (50 for paid users, configurable by admin)
// Uses Groq API with OpenRouter fallback
//
// Required Environment Variables:
//   - GROQ_API_KEY: Your Groq API key from https://console.groq.com/
//   - OPENROUTER_API_KEY: Your OpenRouter API key from https://openrouter.ai/
//   - SERPER_API_KEY: Your Serper API key from https://serper.dev/ (2,500 free searches/month)
//   - FIREBASE_PROJECT_ID: Your Firebase project ID

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
    'Access-Control-Allow-Headers': 'content-type, authorization',
  };
}

// Firestore REST API helper - Get document
async function firestoreGet(projectId, collection, docId, idToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}`;
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${idToken}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (response.status === 404) {
    return null; // Document doesn't exist
  }
  
  if (!response.ok) {
    throw new Error(`Firestore error: ${response.status}`);
  }
  
  const data = await response.json();
  // Convert Firestore format to simple object
  if (data.fields) {
    const result = {};
    for (const [key, value] of Object.entries(data.fields)) {
      result[key] = value.stringValue || value.integerValue || value.doubleValue || value.booleanValue || value.timestampValue || null;
    }
    return result;
  }
  return null;
}

// Firestore REST API helper - Create/Update document
async function firestoreSet(projectId, collection, docId, data, idToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}`;
  
  // Convert simple object to Firestore format
  const fields = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      fields[key] = { stringValue: value };
    } else if (typeof value === 'number') {
      fields[key] = { integerValue: String(value) };
    } else if (typeof value === 'boolean') {
      fields[key] = { booleanValue: value };
    } else if (value instanceof Date) {
      fields[key] = { timestampValue: value.toISOString() };
    }
  }
  
  const response = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${idToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ fields })
  });
  
  if (!response.ok) {
    throw new Error(`Firestore error: ${response.status}`);
  }
  
  return await response.json();
}

// Get user's daily request count from Firestore
async function getUserRequestCount(projectId, userId, dateStr, idToken) {
  try {
    const docId = `${userId}_${dateStr}`;
    const data = await firestoreGet(projectId, 'aiTutorRequests', docId, idToken);
    return data?.count ? parseInt(data.count) : 0;
  } catch (error) {
    console.error('Error getting request count:', error);
    return 0;
  }
}

// Increment user's daily request count (client will write, server verifies)
async function verifyAndIncrementRequestCount(projectId, userId, dateStr, idToken, currentCount) {
  // Server verifies the count is reasonable (not more than expected)
  // Client will write the new count to Firestore
  const newCount = currentCount + 1;
  return newCount;
}

// Get user's max daily requests
async function getUserMaxRequests(projectId, userId, idToken) {
  try {
    const userData = await firestoreGet(projectId, 'users', userId, idToken);
    if (userData?.aiAccessBlocked === 'true' || userData?.aiAccessBlocked === true) {
      return 0;
    }
    return userData?.aiMaxRequestsDaily ? parseInt(userData.aiMaxRequestsDaily) : 50;
  } catch (error) {
    console.error('Error getting user max requests:', error);
    return 50; // Default
  }
}

// Get global provider request count
async function getGlobalProviderCount(projectId, provider, dateStr, idToken) {
  try {
    const docId = `${provider}_${dateStr}`;
    const data = await firestoreGet(projectId, 'aiTutorGlobalStats', docId, idToken);
    return data?.count ? parseInt(data.count) : 0;
  } catch (error) {
    return 0;
  }
}

// Increment global provider count (server writes using service account token)
async function incrementGlobalProviderCount(projectId, provider, dateStr, serviceToken) {
  try {
    const docId = `${provider}_${dateStr}`;
    const current = await firestoreGet(projectId, 'aiTutorGlobalStats', docId, serviceToken);
    const newCount = (current?.count ? parseInt(current.count) : 0) + 1;
    
    await firestoreSet(projectId, 'aiTutorGlobalStats', docId, {
      provider: provider,
      date: dateStr,
      count: String(newCount),
      lastRequestAt: new Date().toISOString()
    }, serviceToken);
    
    return newCount;
  } catch (error) {
    console.error('Error incrementing global count:', error);
    return 0;
  }
}

// Build system prompt with subject information
function buildSystemPrompt(userSubjects, subjectSummaries, subjectSpecifications, userName) {
  // Build detailed exam board information
  let examBoardsInfo = `
Exam Boards Available on GCSEMate:

AQA (Assessment and Qualifications Alliance):
- Biology: GCSE Biology (Triple/Higher) - Specification AQA-8461-SP-2016
- Chemistry: GCSE Chemistry (Triple/Higher) - Specification AQA-8462-SP-2016
- Physics: GCSE Physics (Triple/Higher) - Specification AQA-8463-SP-2016
- English Language: GCSE English Language - Specification AQA-8700-SP-2015
- Mathematics: Level 2 Certificate in Further Mathematics - Specification AQA-8365-SP-2018

Edexcel (Pearson Edexcel):
- Mathematics: GCSE Mathematics (Higher/Foundation) - Specification from 2015
- English Literature: GCSE English Literature - Specification from 2015
- History: GCSE History (9-1) - Specification from 2016
- German: GCSE German - Specification from 2016
- Music: GCSE Music (9-1) - Specification issue 4 from 2016

OCR (Oxford, Cambridge and RSA Examinations):
- Geography: GCSE Geography B - Taught before September 2025, final assessments Summer 2026
- Computing: GCSE Computer Science - Specification J277

Eduqas (WJEC Eduqas):
- Philosophy and Ethics: GCSE Religious Studies (Philosophy & Ethics) - Full specification from 2016
`;

  let subjectsInfo = '';
  if (userSubjects && userSubjects.length > 0) {
    subjectsInfo = '\n\nYou have access to information about the following GCSE subjects that this user is studying:\n';
    userSubjects.forEach(subject => {
      const subjectLower = subject.toLowerCase();
      const summary = subjectSummaries[subjectLower];
      const specs = subjectSpecifications[subjectLower];
      
      if (summary) {
        subjectsInfo += `\n- ${subject}: ${summary.description || summary.summary}`;
        if (specs) {
          const specEntries = Object.entries(specs);
          specEntries.forEach(([board, spec]) => {
            subjectsInfo += `\n  Exam Board: ${board} - ${spec.label}`;
            if (spec.tier) {
              subjectsInfo += ` (${spec.tier})`;
            }
          });
        }
      }
    });
    subjectsInfo += '\n\nIMPORTANT: You should ONLY provide information about the subjects listed above. Do not provide information about subjects the user does not have access to.';
  } else {
    // Free users - assume all subjects
    subjectsInfo = '\n\nYou have access to information about all GCSE subjects available on GCSEMate: Biology, Chemistry, Physics, Mathematics, English Language (AQA), English Literature (Edexcel), History, Geography, Computing, German, Music, and Philosophy and Ethics.';
  }
  
  return `You are GCSEMate AI, an intelligent tutoring assistant created by Mayukhjit Chakraborty for GCSE students in the UK.

Your primary purpose is to help students with:
1. GCSE academic topics across all subjects (Mathematics, English Language AQA, English Literature Edexcel, Sciences, History, Geography, etc.)
2. Questions about GCSEMate platform features and usage

${examBoardsInfo}

${subjectsInfo}

About GCSEMate:
GCSEMate is a free GCSE revision platform (https://gcsemate.com) that provides:
- Organized revision notes and past papers for all GCSE subjects
- Subject-specific resources organized by exam board (AQA, Edexcel, OCR, Eduqas)
- Video playlists and useful links for revision
- Study tools including flashcards, notes, and progress tracking
- AI Tutor (this feature) for academic assistance
- Blog posts with revision tips and exam guidance
- Calendar with exam dates and countdown timers
- File browser to access subject-specific materials

The platform is created by Mayukhjit Chakraborty and is designed to help UK students succeed in their GCSE exams.

Response Guidelines:
- Use clear, educational, and encouraging language appropriate for GCSE students
- Format responses using markdown: use **bold** for emphasis, *italics* for terms, and code blocks for examples
- For mathematical expressions, use LaTeX notation: inline math with \\(...\\) and display math with \\[...\\]
- Break down complex topics into digestible explanations
- Provide step-by-step solutions for problem-solving questions
- Reference specific exam boards when relevant (AQA, Edexcel, OCR, Eduqas) and use the exact exam board names and specifications listed above
- Use UK English spelling and terminology (GCSEs are UK qualifications)
- Keep responses focused and comprehensive but not overly lengthy
- If asked about exam specifications, refer to the specific exam board information provided above with exact specification codes
- IMPORTANT: You have built-in web search capabilities. When you receive web search results in your context, treat them as if you searched the web yourself. Use this information naturally and seamlessly in your responses. Always cite sources using markdown links like [Source Name](URL) when referencing web search results.
- When presenting information from web searches, integrate it naturally into your response - don't explicitly say "I searched the web" unless the user asks how you know. Just present the information confidently as if you naturally have access to current information.
- Format links in your responses using markdown: [Link Text](URL). Always make links clickable and properly formatted.
- If web search results are provided, use them to give accurate, up-to-date information. If you cannot verify information even with search results, apologize and explain you want to provide accurate information.
- Always be safe, harmless, and appropriate
- If asked about non-academic topics unrelated to GCSEs or GCSEMate, politely redirect to GCSE subjects or GCSEMate features

Remember: You're helping students succeed in their GCSE exams. Be supportive, clear, and educational. Always prioritize accuracy - when in doubt, use web search or apologize if you cannot verify information.`;
}

// Sanitize URL to prevent XSS and ensure security
function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return '';
  
  try {
    const urlObj = new URL(url);
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return '';
    }
    // Block potentially dangerous domains (add more if needed)
    const dangerousDomains = ['javascript:', 'data:', 'vbscript:'];
    if (dangerousDomains.some(domain => url.toLowerCase().includes(domain))) {
      return '';
    }
    return url;
  } catch (e) {
    // Invalid URL
    return '';
  }
}

// Sanitize text content to prevent XSS
function sanitizeText(text) {
  if (!text || typeof text !== 'string') return '';
  // Remove potentially dangerous HTML/script tags
  return text
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
}

// Web search using Serper API (2,500 free searches/month)
async function performWebSearch(apiKey, query, conversationHistory = []) {
  try {
    // Enhance query with context if available
    let enhancedQuery = query;
    if (conversationHistory.length > 0) {
      // Add GCSE context to improve search relevance
      const lastMessage = conversationHistory[conversationHistory.length - 1];
      if (lastMessage && lastMessage.role === 'user') {
        enhancedQuery = `GCSE UK ${query}`;
      }
    }
    
    const response = await fetch('https://google.serper.dev/search', {
      method: 'POST',
      headers: {
        'X-API-KEY': apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        q: enhancedQuery,
        num: 5, // Get top 5 results
        gl: 'uk', // UK region for better GCSE results
        hl: 'en' // English language
      })
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Serper API error: ${response.status} - ${errorText}`);
    }
    
    const data = await response.json();
    
    // Format search results naturally for AI (as if it searched itself)
    let searchResults = '';
    if (data.organic && data.organic.length > 0) {
      searchResults = '\n\n[I searched the web and found the following current information:]\n\n';
      data.organic.slice(0, 5).forEach((result, index) => {
        const sanitizedTitle = sanitizeText(result.title || '');
        const sanitizedLink = sanitizeUrl(result.link || '');
        const sanitizedSnippet = sanitizeText(result.snippet || '');
        
        if (sanitizedLink && sanitizedTitle) {
          searchResults += `**${sanitizedTitle}**\n`;
          searchResults += `Source: [${sanitizedLink}](${sanitizedLink})\n`;
          if (sanitizedSnippet) {
            searchResults += `${sanitizedSnippet}\n\n`;
          }
        }
      });
      searchResults += '[End of web search results. Use this information naturally in your response, citing sources with markdown links when relevant.]\n';
    }
    
    return searchResults;
  } catch (error) {
    console.error('Web search error:', error);
    return ''; // Return empty if search fails
  }
}

// Check if message needs web search (intelligent detection)
function needsWebSearch(message, conversationHistory = []) {
  if (!message || typeof message !== 'string') return false;
  
  const lowerMessage = message.toLowerCase();
  
  // Keywords that indicate need for current/up-to-date information
  const webSearchKeywords = [
    // Time-related
    'current', 'recent', 'latest', 'today', 'this year', '2024', '2025', '2026',
    'when is', 'what is the date', 'exam date', 'when does', 'deadline', 'when are',
    // Update-related
    'specification', 'syllabus', 'updated', 'changed', 'new', 'recent changes', 'changes to',
    'new specification', 'latest version', 'current version',
    // Question words that often need current info
    'what are the', 'what is the latest', 'what are the current', 'what are the recent',
    'tell me about', 'find information about', 'search for', 'look up',
    // GCSE-specific current info needs
    'exam dates', 'exam schedule', 'timetable', 'when do exams', 'exam period',
    'results day', 'results date', 'grade boundaries', 'grade boundaries 2024',
    'grade boundaries 2025', 'pass mark', 'what is required', 'what do i need'
  ];
  
  // Check for question patterns
  const questionPatterns = [
    /^when\s+(is|are|do|does|will)/i,
    /^what\s+(is|are|was|were)\s+(the|a|an)?\s*(current|latest|recent|new)/i,
    /^tell\s+me\s+(about|when|what)/i,
    /(current|latest|recent|new)\s+(information|info|details|data)/i
  ];
  
  // Check keywords
  const hasKeyword = webSearchKeywords.some(keyword => lowerMessage.includes(keyword));
  
  // Check question patterns
  const hasQuestionPattern = questionPatterns.some(pattern => pattern.test(message));
  
  // Check if previous conversation suggests need for current info
  let contextSuggestsSearch = false;
  if (conversationHistory.length > 0) {
    const recentContext = conversationHistory.slice(-4).map(m => m.content || '').join(' ').toLowerCase();
    contextSuggestsSearch = /(current|latest|recent|update|change|date|when|deadline)/i.test(recentContext);
  }
  
  return hasKeyword || hasQuestionPattern || contextSuggestsSearch;
}

// Call Groq API
async function callGroqAPI(apiKey, messages) {
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'llama-4-maverick-17b-128e-instruct',
      messages: messages,
      temperature: 0.7,
      max_tokens: 2048,
      stream: false
    })
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Groq API error: ${response.status} - ${errorText}`);
  }
  
  return await response.json();
}

// Call OpenRouter API
async function callOpenRouterAPI(apiKey, messages) {
  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://gcsemate.com',
      'X-Title': 'GCSEMate AI Tutor'
    },
    body: JSON.stringify({
      model: 'tngtech/deepseek-r1t2-chimera:free',
      messages: messages,
      temperature: 0.7,
      max_tokens: 2048
    })
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OpenRouter API error: ${response.status} - ${errorText}`);
  }
  
  return await response.json();
}

export async function onRequest(context) {
  const { request, env } = context;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405);
  }

  try {
    // Get API keys
    const GROQ_API_KEY = env.GROQ_API_KEY;
    const OPENROUTER_API_KEY = env.OPENROUTER_API_KEY;
    const SERPER_API_KEY = env.SERPER_API_KEY; // Web search API key (optional)
    const FIREBASE_PROJECT_ID = env.FIREBASE_PROJECT_ID;
    
    // Check for required environment variables
    if (!FIREBASE_PROJECT_ID) {
      console.error('FIREBASE_PROJECT_ID not configured');
      return json({ 
        error: 'Server configuration error', 
        message: 'Firebase project ID not configured. Please contact support.',
        code: 'CONFIG_ERROR'
      }, 500);
    }
    
    if (!GROQ_API_KEY && !OPENROUTER_API_KEY) {
      console.error('No AI API keys configured');
      return json({ 
        error: 'Server configuration error', 
        message: 'AI service not configured. Please contact support.',
        code: 'CONFIG_ERROR'
      }, 500);
    }

    // Parse request body
    const body = await request.json();
    const { message, userId, conversationHistory = [], userSubjects = [], subjectSummaries = {}, subjectSpecifications = {}, userData: clientUserData, currentRequestCount } = body;

    if (!message || !userId) {
      return json({ error: 'Missing required fields: message, userId' }, 400);
    }

    // Get Firebase ID token from Authorization header
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return json({ error: 'Missing or invalid authorization token' }, 401);
    }
    
    const idToken = authHeader.replace('Bearer ', '');

    // Validate userData structure
    if (!clientUserData || typeof clientUserData !== 'object') {
      return json({ error: 'Missing or invalid userData' }, 400);
    }

    const today = new Date().toISOString().split('T')[0];
    
    // Get user request count from Firestore (server-side verification)
    const userRequestCount = await getUserRequestCount(FIREBASE_PROJECT_ID, userId, today, idToken);
    
    // Verify client's reported count is reasonable (within 1 of server count)
    if (currentRequestCount !== undefined && Math.abs(currentRequestCount - userRequestCount) > 1) {
      // Count mismatch - use server count
      console.warn(`Request count mismatch for ${userId}: client=${currentRequestCount}, server=${userRequestCount}`);
    }

    // Use userData from client (validated structure)
    const userData = {
      tier: clientUserData.tier || 'free',
      role: clientUserData.role || null,
      aiMaxRequestsDaily: clientUserData.aiMaxRequestsDaily !== undefined ? clientUserData.aiMaxRequestsDaily : 50,
      aiAccessBlocked: clientUserData.aiAccessBlocked === true
    };

    const isAdmin = (userData.role || '').toLowerCase() === 'admin';
    const isPaid = userData.tier === 'paid';
    
    // Free users cannot use AI
    if (!isPaid && !isAdmin) {
      return json({ 
        error: 'Access denied', 
        message: 'AI Tutor is available for Pro users only. Please upgrade to access this feature.' 
      }, 403);
    }

    // Check daily request limit (admins have unlimited)
    if (!isAdmin) {
      const maxRequests = await getUserMaxRequests(FIREBASE_PROJECT_ID, userId, idToken);
      
      if (maxRequests === 0) {
        return json({ 
          error: 'Access blocked', 
          message: 'AI Tutor access has been blocked for your account. Please contact support.' 
        }, 403);
      }
      
      if (userRequestCount >= maxRequests) {
        return json({ 
          error: 'Daily limit exceeded', 
          message: `You have reached your daily limit of ${maxRequests} requests. Please try again tomorrow.`,
          requestsUsed: userRequestCount,
          requestsRemaining: 0,
          maxRequests: maxRequests
        }, 429);
      }
    }

    // Get user's display name from userData
    const userName = clientUserData.displayName || clientUserData.name || 'there';
    
    // Check if this is the first interaction (name greeting)
    const isFirstInteraction = conversationHistory.length === 0;
    const nameConfirmed = body.nameConfirmed === true;
    
    // Get max requests (needed for name greeting response)
    const maxRequests = isAdmin ? -1 : (await getUserMaxRequests(FIREBASE_PROJECT_ID, userId, idToken));
    
    // Handle name greeting for first interaction - return without API call
    if (isFirstInteraction && !nameConfirmed) {
      // This is the initial greeting - return it without calling API (saves a request)
      return json({
        response: `Hello! I'm GCSEMate AI, your intelligent tutoring assistant. I see your name is ${userName}. Is it okay if I call you ${userName}? If you'd prefer a different name, just let me know what you'd like me to call you!`,
        provider: 'system',
        requestsUsed: userRequestCount,
        requestsRemaining: isAdmin ? -1 : Math.max(0, maxRequests - userRequestCount),
        maxRequests: isAdmin ? -1 : maxRequests,
        shouldIncrement: false, // Don't increment for name greeting
        isNameGreeting: true
      });
    }
    
    // Build system prompt for normal interactions
    const systemPrompt = buildSystemPrompt(userSubjects, subjectSummaries, subjectSpecifications, userName);
    
    // Check if web search is needed (intelligent detection)
    let webSearchResults = '';
    let usedWebSearch = false;
    
    if (SERPER_API_KEY && needsWebSearch(message, conversationHistory)) {
      try {
        webSearchResults = await performWebSearch(SERPER_API_KEY, message, conversationHistory);
        usedWebSearch = webSearchResults.length > 0;
      } catch (searchError) {
        console.error('Web search failed:', searchError);
        // Continue without web search results - fail silently for better UX
      }
    }
    
    // Build messages array with web search results seamlessly integrated
    let messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory.slice(-10), // Keep last 10 messages for context
    ];
    
    // Add user message with web search results if available
    if (webSearchResults) {
      // Add search results as context before user message for seamless integration
      messages.push({ 
        role: 'user', 
        content: `${message}\n\n${webSearchResults}` 
      });
    } else {
      messages.push({ role: 'user', content: message });
    }

    // Try Groq first (if available and under limit)
    let aiResponse = null;
    let provider = null;
    let error = null;
    
    const GROQ_DAILY_LIMIT = 14400;
    
    if (GROQ_API_KEY) {
      try {
        const globalGroqCount = await getGlobalProviderCount(FIREBASE_PROJECT_ID, 'groq', today, idToken);
        
        if (globalGroqCount < GROQ_DAILY_LIMIT) {
          const groqData = await callGroqAPI(GROQ_API_KEY, messages);
          aiResponse = groqData.choices[0]?.message?.content || null;
          provider = 'groq';
          
          // Increment global Groq count (client will write via Firestore rules)
          // For now, we'll track it but client writes it
        } else {
          throw new Error('Groq daily limit reached');
        }
      } catch (groqError) {
        console.error('Groq API error:', groqError);
        error = groqError;
        // Will fallback to OpenRouter
      }
    }

    // Fallback to OpenRouter if Groq failed or unavailable
    if (!aiResponse && OPENROUTER_API_KEY) {
      try {
        const OPENROUTER_DAILY_LIMIT = 50; // Total for all users
        const OPENROUTER_USER_LIMIT = 25; // Per user
        
        const globalOpenRouterCount = await getGlobalProviderCount(FIREBASE_PROJECT_ID, 'openrouter', today, idToken);
        const userOpenRouterCount = await getUserRequestCount(FIREBASE_PROJECT_ID, `${userId}_openrouter`, today, idToken);
        
        // Check global limit
        if (globalOpenRouterCount >= OPENROUTER_DAILY_LIMIT) {
          throw new Error('OpenRouter daily limit reached');
        }
        
        // Check user limit (if not admin)
        if (!isAdmin && userOpenRouterCount >= OPENROUTER_USER_LIMIT) {
          throw new Error('OpenRouter user limit reached');
        }
        
        const openRouterData = await callOpenRouterAPI(OPENROUTER_API_KEY, messages);
        aiResponse = openRouterData.choices[0]?.message?.content || null;
        provider = 'openrouter';
      } catch (openRouterError) {
        console.error('OpenRouter API error:', openRouterError);
        error = openRouterError;
      }
    }

    if (!aiResponse) {
      return json({ 
        error: 'AI service unavailable', 
        message: 'All AI services are currently unavailable or have reached their limits. Please try again later.',
        details: error?.message || 'Unknown error'
      }, 503);
    }

    // Check if user confirmed name in this message (if it was first interaction)
    const nameConfirmationPattern = /(yes|yeah|yep|sure|ok|okay|correct|that's right|that's fine|that works|sounds good|call me|my name is)/i;
    const nameNowConfirmed = isFirstInteraction && nameConfirmationPattern.test(message);
    
    // Only increment request count if name is confirmed (or was already confirmed)
    const shouldCountRequest = nameConfirmed || nameNowConfirmed || !isFirstInteraction;
    
    // Calculate new request count (client will write to Firestore)
    const newRequestCount = isAdmin ? userRequestCount : (shouldCountRequest ? userRequestCount + 1 : userRequestCount);
    const requestsRemaining = isAdmin ? -1 : Math.max(0, maxRequests - newRequestCount);

    return json({
      response: aiResponse,
      provider: provider,
      requestsUsed: newRequestCount,
      requestsRemaining: requestsRemaining,
      maxRequests: maxRequests,
      shouldIncrement: !isAdmin && shouldCountRequest, // Tell client to increment count in Firestore
      isNameGreeting: false,
      nameConfirmed: nameNowConfirmed || nameConfirmed
    });

  } catch (error) {
    console.error('AI Tutor function error:', error);
    console.error('Error stack:', error.stack);
    
    // Return more informative error for debugging
    return json({ 
      error: 'Internal server error', 
      message: 'An unexpected error occurred. Please try again later.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      code: 'INTERNAL_ERROR'
    }, 500);
  }
}
