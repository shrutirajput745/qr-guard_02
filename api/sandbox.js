const QRBehaviorSandbox = require('../public/js/behavior-sandbox');

const MAX_API_PAYLOAD_CHARS = 16384;

/**
 * Vercel Serverless Function: POST /api/sandbox
 * Simulates pre-navigation QR payload behavior offline without fetching URLs or executing code.
 */
module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method Not Allowed',
      message: 'Only POST requests are accepted at /api/sandbox'
    });
  }

  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const hasQrData = Object.prototype.hasOwnProperty.call(body, 'qrData') && body.qrData !== undefined && body.qrData !== null;
    const hasUrl = Object.prototype.hasOwnProperty.call(body, 'url') && body.url !== undefined && body.url !== null;
    const hasPayload = Object.prototype.hasOwnProperty.call(body, 'payload') && body.payload !== undefined && body.payload !== null;
    const rawData = hasQrData ? body.qrData : (hasUrl ? body.url : (hasPayload ? body.payload : undefined));

    if (rawData === undefined || rawData === null) {
      return res.status(400).json({
        error: 'Missing qrData parameter.',
        message: 'Please provide a JSON body with { "qrData": "<payload>" }'
      });
    }
    if (typeof rawData !== 'string') {
      return res.status(400).json({
        error: 'Invalid qrData type.',
        message: 'qrData must be a string payload.'
      });
    }
    if (rawData.length > MAX_API_PAYLOAD_CHARS) {
      return res.status(413).json({
        error: 'Payload Too Large',
        message: `Payload exceeds maximum allowed length of ${MAX_API_PAYLOAD_CHARS} characters.`
      });
    }

    const simulation = QRBehaviorSandbox.simulate(rawData);
    return res.status(200).json(simulation);
  } catch (err) {
    console.error('Sandbox simulation error:', err && err.message ? err.message : err);
    return res.status(500).json({
      error: 'Internal Sandbox Error',
      message: 'Unable to simulate the provided QR payload.'
    });
  }
};
