// Stripe Billing Portal session creator
// Env vars required:
// - STRIPE_SECRET_KEY
// Optional:
// - STRIPE_PORTAL_RETURN_URL (default: https://gcsemate.com/account)

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

async function findCustomerByEmail(email) {
  if (!email) return null;
  const list = await stripe.customers.list({ email, limit: 1 });
  return list.data && list.data.length ? list.data[0] : null;
}

async function handler(req, res) {
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
    const customerId = body.customerId;
    const customerEmail = body.customerEmail;

    let customer = null;
    if (customerId) {
      customer = await stripe.customers.retrieve(customerId);
    } else {
      customer = await findCustomerByEmail(customerEmail);
    }

    if (!customer || customer.deleted) {
      return send(res, 404, { error: 'Customer not found. Complete a checkout first.' });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: customer.id,
      return_url: process.env.STRIPE_PORTAL_RETURN_URL || 'https://gcsemate.com/account'
    });

    return send(res, 200, { url: session.url });
  } catch (error) {
    console.error('stripe-portal error', error);
    return send(res, 500, { error: 'Unable to create billing portal session' });
  }
}

export default handler;
module.exports = handler;
