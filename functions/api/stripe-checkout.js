// Stripe Checkout session creator for subscription payments
// Env vars required:
// - STRIPE_SECRET_KEY
// Optional:
// - STRIPE_SUCCESS_URL (default: https://gcsemate.com/?checkout=success)
// - STRIPE_CANCEL_URL (default: https://gcsemate.com/?checkout=cancel)

const stripeSecret = process.env.STRIPE_SECRET_KEY;
const stripe = stripeSecret ? require('stripe')(stripeSecret) : null;

async function readJsonBody(req) {
  let body = '';
  await new Promise((resolve) => {
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', resolve);
  });
  try { return JSON.parse(body || '{}'); } catch (_) { return {}; }
}

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

async function handler(req, res) {
  // Basic CORS for browser calls
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return send(res, 405, { error: 'Method not allowed' });
  }

  if (!stripe) {
    return send(res, 500, { error: 'Stripe secret key not configured' });
  }

  try {
    const body = await readJsonBody(req);
    const priceId = body.priceId;
    const customerEmail = body.customerEmail;
    const mode = body.mode === 'payment' ? 'payment' : 'subscription';

    if (!priceId) {
      return send(res, 400, { error: 'priceId required' });
    }

    const session = await stripe.checkout.sessions.create({
      mode,
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      customer_email: customerEmail || undefined,
      billing_address_collection: 'auto',
      metadata: {
        priceId,
        mode,
        email: customerEmail || 'unknown',
        createdFrom: 'gcsemate-web'
      },
      success_url: process.env.STRIPE_SUCCESS_URL || 'https://gcsemate.com/?checkout=success',
      cancel_url: process.env.STRIPE_CANCEL_URL || 'https://gcsemate.com/?checkout=cancel'
    });

    return send(res, 200, { url: session.url });
  } catch (error) {
    console.error('stripe-checkout error', error);
    return send(res, 500, { error: 'Unable to create checkout session' });
  }
}

export default handler;
module.exports = handler;
