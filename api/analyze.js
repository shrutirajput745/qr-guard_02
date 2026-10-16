const QRAnalyzer = require('../public/js/analyzer');

/**
 * Vercel Serverless Function: POST /api/analyze
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
    const rawData = req.body?.qrData || req.body?.url || req.body?.payload;

    if (rawData === undefined || rawData === null) {
      return res.status(400).json({
        error: 'Missing qrData parameter.',
        message: 'Please provide a JSON body with { "qrData": "<payload>" }'
      });
    }

    const analysis = QRAnalyzer.analyze(rawData);
    return res.status(200).json(analysis);
  } catch (err) {
    console.error('Analysis error:', err);
    return res.status(500).json({
      error: 'Internal Analysis Error',
      message: err.message
    });
  }
};
