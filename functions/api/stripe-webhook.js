// Stripe webhook handler
// Env vars required:
// - STRIPE_SECRET_KEY
// - STRIPE_WEBHOOK_SECRET
// Optional (to write to Firestore via service account):
// - FIREBASE_PROJECT_ID
// - FIREBASE_CLIENT_EMAIL
// - FIREBASE_PRIVATE_KEY (use \n for newlines)
// The Firestore write is best-effort; if creds are missing, we just acknowledge events.

const crypto = require('crypto');
const stripeSecret = process.env.STRIPE_SECRET_KEY;
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
const stripe = stripeSecret ? require('stripe')(stripeSecret) : null;

const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const rawPrivateKey = process.env.FIREBASE_PRIVATE_KEY;
const privateKey = rawPrivateKey ? rawPrivateKey.replace(/\\n/g, '\n') : null;

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

async function readRawBody(req) {
  const chunks = [];
  await new Promise((resolve) => {
    req.on('data', (c) => chunks.push(Buffer.from(c)));
    req.on('end', resolve);
  });
  return Buffer.concat(chunks);
}

function buildJwt() {
  if (!projectId || !clientEmail || !privateKey) return null;
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: clientEmail,
    sub: clientEmail,
    aud: 'https://oauth2.googleapis.com/token',
    scope: 'https://www.googleapis.com/auth/datastore',
    iat,
    exp
  };
  const base64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsigned = `${base64url(header)}.${base64url(payload)}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  const signature = signer.sign(privateKey, 'base64url');
  return `${unsigned}.${signature}`;
}

async function getAccessToken() {
  const jwt = buildJwt();
  if (!jwt) return null;
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    }).toString()
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data.access_token || null;
}

function toDocId(email) {
  if (!email) return 'unknown';
  return email.replace(/[^a-zA-Z0-9_-]/g, '_');
}

async function writeFirestoreStatus({ email, customerId, subscriptionId, priceId, status, currentPeriodEnd }) {
  if (!projectId || !clientEmail || !privateKey) return { skipped: true, reason: 'missing service account env' };
  const token = await getAccessToken();
  if (!token) return { skipped: true, reason: 'oauth token missing' };

  const docId = toDocId(email || customerId || 'unknown');
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/stripeCustomers/${docId}?updateMask.fieldPaths=status&updateMask.fieldPaths=email&updateMask.fieldPaths=customerId&updateMask.fieldPaths=subscriptionId&updateMask.fieldPaths=priceId&updateMask.fieldPaths=currentPeriodEnd&updateMask.fieldPaths=updatedAt`;

  const body = {
    fields: {
      status: { stringValue: status || 'unknown' },
      email: email ? { stringValue: email } : undefined,
      customerId: customerId ? { stringValue: customerId } : undefined,
      subscriptionId: subscriptionId ? { stringValue: subscriptionId } : undefined,
      priceId: priceId ? { stringValue: priceId } : undefined,
      currentPeriodEnd: Number.isFinite(currentPeriodEnd) ? { integerValue: currentPeriodEnd } : undefined,
      updatedAt: { timestampValue: new Date().toISOString() }
    }
  };
  // Remove undefined fields to avoid API complaints
  Object.keys(body.fields).forEach((k) => { if (body.fields[k] === undefined) delete body.fields[k]; });

  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    return { skipped: true, reason: `firestore write failed ${res.status} ${txt}` };
  }
  return { ok: true };
}

function extractEventData(event) {
  const type = event.type;
  const obj = event.data && event.data.object ? event.data.object : {};
  const base = {
    type,
    customerId: obj.customer || obj.id || null,
    email: obj.customer_details?.email || obj.metadata?.email || obj.email || null,
    priceId: obj.subscription && obj.subscription.items ? null : obj.metadata?.priceId || null,
    subscriptionId: obj.subscription || obj.id || null,
    status: obj.status || null,
    currentPeriodEnd: obj.current_period_end || null
  };

  if (type === 'checkout.session.completed') {
    return {
      type,
      customerId: obj.customer || null,
      email: obj.customer_details?.email || obj.metadata?.email || null,
      priceId: obj.metadata?.priceId || (obj.display_items && obj.display_items[0]?.plan?.id) || null,
      subscriptionId: obj.subscription || null,
      status: 'active',
      currentPeriodEnd: null
    };
  }

  if (type === 'customer.subscription.updated' || type === 'customer.subscription.created' || type === 'customer.subscription.deleted') {
    const itemPrice = Array.isArray(obj.items?.data) ? obj.items.data[0]?.price?.id : null;
    return {
      type,
      customerId: obj.customer || null,
      email: obj.metadata?.email || null,
      priceId: itemPrice,
      subscriptionId: obj.id || null,
      status: obj.status || null,
      currentPeriodEnd: obj.current_period_end || null
    };
  }

  return base;
}

async function handler(req, res) {
  if (!stripe || !webhookSecret) {
    return send(res, 500, { error: 'Stripe webhook not configured' });
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (e) {
    return send(res, 400, { error: 'Cannot read body' });
  }

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, sig, webhookSecret);
  } catch (err) {
    console.error('stripe-webhook signature error', err.message);
    return send(res, 400, { error: 'Invalid signature' });
  }

  const data = extractEventData(event) || {};
  console.log('stripe-webhook event', { type: event.type, data });

  if (projectId && clientEmail && privateKey) {
    try {
      const writeResult = await writeFirestoreStatus(data);
      if (writeResult?.skipped) {
        console.warn('Firestore write skipped', writeResult.reason);
      }
    } catch (e) {
      console.error('Firestore write failed', e);
    }
  }

  return send(res, 200, { received: true });
}

export default handler;
module.exports = handler;
