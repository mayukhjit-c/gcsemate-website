// Hosted Stripe Billing Portal login link for all customers.
// Customers authenticate with their email address and a one-time passcode.

const STRIPE_BILLING_PORTAL_URL = 'https://billing.stripe.com/p/login/4gM8wO6ZT0280mg3CZfAc00';

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
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  if (!['GET', 'POST'].includes(req.method)) {
    res.setHeader('Allow', 'GET, POST, OPTIONS');
    return send(res, 405, { error: 'Method not allowed' });
  }

  return send(res, 200, {
    url: STRIPE_BILLING_PORTAL_URL,
    message: 'Open the hosted Stripe billing portal and sign in with email plus one-time passcode.'
  });
}

export default handler;
module.exports = handler;
