const express = require('express');
const path = require('path');
const analyzeHandler = require('./api/analyze');
const healthHandler = require('./api/health');
const sandboxHandler = require('./api/sandbox');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: 'Invalid JSON payload.',
      message: 'Request body must contain valid JSON.'
    });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Payload Too Large',
      message: 'Request body exceeds server size limit.'
    });
  }
  if (err) {
    return res.status(err.status || 400).json({
      error: 'Bad Request',
      message: 'Unable to parse request payload.'
    });
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// Serverless API handlers mapped to Express routes
app.all('/api/health', healthHandler);
app.all('/api/analyze', analyzeHandler);
app.all('/api/sandbox', sandboxHandler);
app.all('/api/*', (req, res) => {
  res.status(404).json({ error: 'API Endpoint Not Found' });
});

// Single-page application route fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server if run directly
if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`🚀 QR Guard running at http://localhost:${PORT}`);
  });

  process.on('SIGTERM', () => {
    server.close(() => console.log('Server terminated'));
  });
}

module.exports = app;
