/**
 * Vercel Serverless Function: GET /api/health
 */
module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'QR Guard - Security Engine',
    environment: process.env.VERCEL ? 'vercel-production' : 'node-environment',
    version: '1.0.0'
  });
};
