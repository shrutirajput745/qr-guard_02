const http = require('http');
const app = require('../server');
const analyzeServerlessHandler = require('../api/analyze');
const healthServerlessHandler = require('../api/health');

let server;
const PORT = 3001; // Separate port for testing

function makeRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: 'localhost',
      port: PORT,
      ...options
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(body);
        } catch (e) {
          json = body;
        }
        resolve({ statusCode: res.statusCode, headers: res.headers, body: json });
      });
    });

    req.on('error', reject);

    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

// Mock Serverless response generator
function createMockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader: function(k, v) { this.headers[k] = v; return this; },
    status: function(code) { this.statusCode = code; return this; },
    json: function(data) { this.body = data; return this; },
    end: function() { return this; }
  };
  return res;
}

async function runApiTests() {
  console.log('=== QR GUIDE 2: API & SERVER INTEGRATION TESTS ===');
  
  await new Promise((resolve) => {
    server = app.listen(PORT, () => {
      console.log(`Test server running on http://localhost:${PORT}`);
      resolve();
    });
  });

  let passed = 0;
  let failed = 0;

  try {
    // Test 1: GET /api/health
    const healthRes = await makeRequest({ path: '/api/health', method: 'GET' });
    if (healthRes.statusCode === 200 && healthRes.body.status === 'ok') {
      passed++;
      console.log('  ✔ [PASS] GET /api/health returns 200 OK');
    } else {
      failed++;
      console.log('  ✖ [FAIL] GET /api/health returned:', healthRes);
    }

    // Test 2: POST /api/analyze with safe URL
    const safeRes = await makeRequest({
      path: '/api/analyze',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { qrData: 'https://wikipedia.org' });

    if (safeRes.statusCode === 200 && safeRes.body.status === 'Safe' && safeRes.body.score === 0) {
      passed++;
      console.log('  ✔ [PASS] POST /api/analyze safe URL returns Score: 0, Status: Safe');
    } else {
      failed++;
      console.log('  ✖ [FAIL] POST /api/analyze safe URL failed:', safeRes.body);
    }

    // Test 3: POST /api/analyze with phishing URL (test-api.js payload)
    const phishRes = await makeRequest({
      path: '/api/analyze',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { qrData: 'http://free-reward-claim.top/login' });

    if (phishRes.statusCode === 200 && phishRes.body.status === 'Dangerous' && phishRes.body.score >= 70) {
      passed++;
      console.log(`  ✔ [PASS] POST /api/analyze phishing payload returns Score: ${phishRes.body.score}, Status: Dangerous`);
    } else {
      failed++;
      console.log('  ✖ [FAIL] POST /api/analyze phishing payload failed:', phishRes.body);
    }

    // Test 4: POST /api/analyze with missing body parameter (validation error)
    const emptyRes = await makeRequest({
      path: '/api/analyze',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {});

    if (emptyRes.statusCode === 400 && emptyRes.body.error) {
      passed++;
      console.log('  ✔ [PASS] POST /api/analyze missing payload returns 400 Bad Request');
    } else {
      failed++;
      console.log('  ✖ [FAIL] POST /api/analyze missing payload failed:', emptyRes);
    }

    // Test 5: GET / (Frontend Static HTML Serving)
    const staticRes = await makeRequest({ path: '/', method: 'GET' });
    if (staticRes.statusCode === 200 && typeof staticRes.body === 'string' && staticRes.body.includes('QR Guide')) {
      passed++;
      console.log('  ✔ [PASS] GET / serves index.html with 200 OK');
    } else {
      failed++;
      console.log('  ✖ [FAIL] GET / failed to serve index.html');
    }

    // Test 6: GET /css/style.css
    const cssRes = await makeRequest({ path: '/css/style.css', method: 'GET' });
    if (cssRes.statusCode === 200) {
      passed++;
      console.log('  ✔ [PASS] GET /css/style.css static asset loaded successfully');
    } else {
      failed++;
      console.log('  ✖ [FAIL] GET /css/style.css failed');
    }

    // Test 7: Direct Vercel Serverless Function Execution (CORS & Method Validation)
    const mockOptionsRes = createMockRes();
    analyzeServerlessHandler({ method: 'OPTIONS' }, mockOptionsRes);
    if (mockOptionsRes.statusCode === 200 && mockOptionsRes.headers['Access-Control-Allow-Origin'] === '*') {
      passed++;
      console.log('  ✔ [PASS] Vercel Serverless api/analyze handles CORS OPTIONS preflight');
    } else {
      failed++;
      console.log('  ✖ [FAIL] Vercel Serverless CORS preflight failed');
    }

    const mockMethodRes = createMockRes();
    analyzeServerlessHandler({ method: 'GET' }, mockMethodRes);
    if (mockMethodRes.statusCode === 405) {
      passed++;
      console.log('  ✔ [PASS] Vercel Serverless api/analyze rejects non-POST requests with 405 Method Not Allowed');
    } else {
      failed++;
      console.log('  ✖ [FAIL] Vercel Serverless method check failed');
    }

    console.log(`\nAPI Test Results: ${passed} Passed, ${failed} Failed out of 8 Tests\n`);

  } catch (err) {
    console.error('Fatal API test error:', err);
    failed++;
  } finally {
    if (server) {
      await new Promise(r => server.close(r));
    }
  }

  if (failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runApiTests();
}

module.exports = runApiTests;
