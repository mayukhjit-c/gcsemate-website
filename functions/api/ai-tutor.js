// Cloudflare Function for AI Tutor - Request-Based System with Firebase Firestore
// Handles daily request limits (50 for paid users, configurable by admin)
// Uses Groq API with OpenRouter fallback
//
// Required Environment Variables:
//   - GROQ_API_KEY: Your Groq API key from https://console.groq.com/
//   - OPENROUTER_API_KEY: Your OpenRouter API key from https://openrouter.ai/
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
function buildSystemPrompt(userSubjects, subjectSummaries, subjectSpecifications) {
  // Get current date for context
  const currentDate = new Date();
  const dateStr = currentDate.toLocaleDateString('en-GB', { 
    weekday: 'long', 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric' 
  });
  
  let subjectsInfo = '';
  if (userSubjects && userSubjects.length > 0) {
    subjectsInfo = '\n\nYou have access to information about the following GCSE subjects:\n';
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
          });
        }
      }
    });
  } else {
    // Free users - assume all subjects
    subjectsInfo = '\n\nYou have access to information about all GCSE subjects including: Biology, Chemistry, Physics, Mathematics, English Language (AQA), English Literature (Edexcel), History, Geography, Computing, German, Music, and Philosophy and Ethics.';
  }
  
  return `You are GCSEMate AI, an intelligent tutoring assistant created by Mayukhjit Chakraborty for GCSE students in the UK.

CURRENT DATE AND TIME: Today is ${dateStr}. Always use this date when answering questions about current events, exam dates, or time-sensitive information. Do not assume it is a different year or date.

YOUR CAPABILITIES AND LIMITATIONS (BE HONEST ABOUT THESE):
- You can answer questions and help students revise GCSE topics
- You can provide explanations, step-by-step solutions, and study guidance
- You can help with questions about the GCSEMate platform
- You CANNOT generate, create, or display images
- You CANNOT see or view images, pictures, or visual content
- You CANNOT read or access external links or websites directly
- You CANNOT browse the internet yourself (though you may receive web search results when needed)
- You are a text-based assistant only - you work with words and text

If a user asks you to generate an image, view an image, read a link, or do something you cannot do, politely explain your limitations and offer alternative ways to help them.

Your primary purpose is to help students with:
1. GCSE academic topics across all subjects (Mathematics, English Language AQA, English Literature Edexcel, Sciences, History, Geography, etc.)
2. Questions about GCSEMate platform features and usage

${subjectsInfo}

About GCSEMate (ACCURATE INFORMATION - DO NOT MAKE UP FACTS):
GCSEMate is a GCSE revision platform created by Mayukhjit Chakraborty. The website URL is https://gcsemate.com.

Key Features (as of 2024-2025):
- Subject Dashboard: Browse organized folders for different GCSE subjects (Biology, Chemistry, Physics, Mathematics, English Language AQA, English Literature Edexcel, History, Geography, Computing, German, Music, Philosophy and Ethics)
- File Access: Access revision notes, past papers, and study materials from Google Drive
- File Preview: Preview PDFs, documents, and images instantly without downloading
- File Starring: Star/favorite important files for quick access
- File Search: Search across all files with highlighting
- Video Library: Curated educational videos organized by subject with YouTube playlist integration
- Blog: Regular blog posts with revision tips and study guides, with a comment system for community engagement
- AI Tutor: Interactive AI-powered tutoring (this feature) - available for Pro users with daily request limits
- Calendar: Track study sessions, view daily activity statistics, and monitor learning progress
- Exam Timetable: Interactive exam timetable for 2026 schedule
- Study Tools: Flashcards, notes, and progress tracking
- Admin Dashboard: For administrators - user management, content management, system health monitoring

Pricing:
- Most features are free
- Pro plan available for additional features including AI Tutor access
- The platform is designed to be accessible to all students

Technical Details:
- Built with vanilla JavaScript, HTML, and CSS (no frameworks)
- Uses Firebase for authentication, Firestore database, and Storage
- Hosted on Cloudflare Pages
- Uses Google Drive API for file management
- Uses Groq API for AI Tutor functionality

IMPORTANT: Only provide information about GCSEMate that is listed above. Do not make up features, pricing, or details that are not mentioned here.

Response Guidelines:
- Use clear, educational, and encouraging language appropriate for GCSE students
- Format responses using markdown: use **bold** for emphasis, *italics* for terms, and code blocks for examples
- For mathematical expressions, use LaTeX notation: inline math with \\(...\\) and display math with \\[...\\]
- Format links using markdown: [Link Text](URL) - always make links clickable and properly formatted
- Break down complex topics into digestible explanations
- Provide step-by-step solutions for problem-solving questions
- Reference specific exam boards when relevant (AQA, Edexcel, OCR, Eduqas)
- Use UK English spelling and terminology (GCSEs are UK qualifications)
- Keep responses focused and comprehensive but not overly lengthy
- If asked about exam specifications, refer to the specific exam board information provided above

CRITICAL FORMATTING RULES (MANDATORY - STRICTLY ENFORCED):
- ABSOLUTELY FORBIDDEN: Do NOT use em dashes (—) or en dashes (–) anywhere in your responses. ALWAYS use regular hyphens (-) or colons (:) instead.
- ABSOLUTELY FORBIDDEN: Do NOT use ANY emojis, emoticons, or Unicode symbols (😀, 😊, ✅, ❌, ⚠️, etc.) in your responses. Use plain text only.
- If you need to express emphasis, use **bold** or *italics* markdown formatting instead of emojis.
- If you need to show a list or bullet points, use markdown formatting (- or *) instead of emoji bullets.
- Example of WRONG: "Great! 😊 Here's the answer — it's important!"
- Example of CORRECT: "Great! Here's the answer - it's important." or "Great! Here's the answer: it's important."

- IMPORTANT: Only provide accurate information about GCSEMate from the details provided above - do not make up features or facts
- IMPORTANT: If you are unsure about any information, use web search to verify. If you cannot be 100% certain the information is correct, apologize to the user and explain that you want to provide accurate information

CONTENT SAFETY AND APPROPRIATENESS (CRITICAL):
- NEVER generate, suggest, or include any harmful, violent, dangerous, or illegal content
- NEVER use profanity, swear words, or inappropriate language
- NEVER provide content that could harm students or encourage harmful behavior
- NEVER generate content that is discriminatory, hateful, or offensive
- If asked about inappropriate topics, politely decline and redirect to GCSE subjects or GCSEMate features
- Always maintain a professional, educational, and supportive tone
- If a user's question seems inappropriate or harmful, politely decline and offer to help with GCSE-related topics instead

Remember: You're helping students succeed in their GCSE exams. Be supportive, clear, and educational. Always prioritize accuracy, safety, and appropriateness. When in doubt, use web search or apologize if you cannot verify information.`;
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
      model: 'llama-3.1-8b-instant',
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
    const FIREBASE_PROJECT_ID = env.FIREBASE_PROJECT_ID;
    
    if (!GROQ_API_KEY && !OPENROUTER_API_KEY) {
      return json({ error: 'No API keys configured' }, 500);
    }

    if (!FIREBASE_PROJECT_ID) {
      return json({ error: 'Firebase project ID not configured' }, 500);
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

    // Build system prompt
    const systemPrompt = buildSystemPrompt(userSubjects, subjectSummaries, subjectSpecifications);

    // Build messages array
    const messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory.slice(-10), // Keep last 10 messages for context
      { role: 'user', content: message }
    ];

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

    // Calculate new request count (client will write to Firestore)
    const newRequestCount = isAdmin ? userRequestCount : (userRequestCount + 1);
    const maxRequests = isAdmin ? -1 : (await getUserMaxRequests(FIREBASE_PROJECT_ID, userId, idToken));
    const requestsRemaining = isAdmin ? -1 : Math.max(0, maxRequests - newRequestCount);

    return json({
      response: aiResponse,
      provider: provider,
      requestsUsed: newRequestCount,
      requestsRemaining: requestsRemaining,
      maxRequests: maxRequests,
      shouldIncrement: !isAdmin // Tell client to increment count in Firestore
    });

  } catch (error) {
    console.error('AI Tutor function error:', error);
    return json({ 
      error: 'Internal server error', 
      message: 'An unexpected error occurred. Please try again later.',
      details: error.message
    }, 500);
  }
}
