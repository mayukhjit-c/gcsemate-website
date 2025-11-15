# AI Tutor Setup Guide

This guide explains how to set up the AI Tutor feature.

## Overview

The AI Tutor provides AI-powered tutoring assistance for GCSE students using Groq's Llama 3.1 8B model. It includes:
- **Rate limiting**: 30 requests per minute per user
- **Token tracking**: Daily token consumption tracking (max 64,000 tokens per user)

## Prerequisites

1. Cloudflare account with Pages project set up
2. Groq API key (get from https://console.groq.com/)

## Setup Steps

### Step 1: Get Groq API Key

1. Go to https://console.groq.com/
2. Sign up or log in
3. Navigate to API Keys section
4. Create a new API key
5. Copy the API key (you'll need it in the next step)

### Step 2: Configure Environment Variables

1. In your Cloudflare Pages project, go to **Settings** → **Environment Variables** (or **Variables and Secrets**)
2. Click **Add variable**
3. Add the following variable:
   - **Variable name**: `GROQ_API_KEY`
   - **Value**: Your Groq API key from Step 1
   - **Environment**: Production (and Preview if needed)
4. Click **Save**

### Step 3: Deploy

1. The AI Tutor function is already in your codebase at `functions/api/ai-tutor.js`
2. Deploy your Pages project (the function will be automatically included)
3. The AI Tutor will be available at `/api/ai-tutor`

## How It Works

- Rate limiting and token tracking use in-memory storage
- Data resets on function restart (acceptable for most use cases)
- The function automatically handles rate limiting and token tracking

## Testing

After deployment:
1. Navigate to the AI Tutor page in your app
2. Make a test request
3. Check that responses are working correctly
4. Verify rate limiting (try making 31 requests quickly - should get rate limit error)

## Troubleshooting

### "Groq API key not configured"
- Make sure you added `GROQ_API_KEY` in Cloudflare Pages environment variables
- Check that the variable name is exactly `GROQ_API_KEY` (case-sensitive)
- Redeploy after adding the variable

### "Rate limit exceeded"
- This is expected behavior - 30 requests per minute limit
- Wait 60 seconds and try again

### "Token limit exceeded"
- Daily limit of 64,000 tokens reached
- Wait until the next day (resets daily)

## Additional Resources

- [Groq API Documentation](https://console.groq.com/docs)
- [Cloudflare Pages Functions](https://developers.cloudflare.com/pages/platform/functions/)
