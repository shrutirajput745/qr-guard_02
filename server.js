const express = require('express');
const path = require('path');
const analyzeHandler = require('./api/analyze');
const healthHandler = require('./api/health');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Serverless API handlers mapped to Express routes
app.all('/api/health', healthHandler);
app.all('/api/analyze', analyzeHandler);

// Single-page application route fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server if run directly
if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`🚀 QR Guide 2 running at http://localhost:${PORT}`);
  });

  process.on('SIGTERM', () => {
    server.close(() => console.log('Server terminated'));
  });
}

module.exports = app;
