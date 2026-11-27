const QRAnalyzer = require('../public/js/analyzer');

const MAX_API_PAYLOAD_CHARS = 16384;

/**
 * Vercel Serverless Function: POST /api/analyze
 * Performs offline deterministic QR classification, threat intelligence, and URL forensics.
 */
module.exports = (req, res) => {
  // CORS Headers
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
      message: 'Only POST requests are accepted at /api/analyze'
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

    const analysis = QRAnalyzer.analyze(rawData);
    return res.status(200).json(analysis);
  } catch (err) {
    console.error('Analysis error:', err && err.message ? err.message : err);
    return res.status(500).json({
      error: 'Internal Analysis Error',
      message: 'Unable to analyze the provided QR payload.'
    });
  }
};
