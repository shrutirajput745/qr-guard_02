const http = require('http');

const data = JSON.stringify({
  qrData: 'http://free-reward-claim.top/login'
});

const req = http.request({
  hostname: 'localhost',
  port: 3000,
  path: '/api/analyze',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  }
}, (res) => {
  let body = '';
  res.on('data', chunk => body += chunk);
  res.on('end', () => {
    console.log('API RESPONSE STATUS:', res.statusCode);
    console.log('API RESPONSE BODY:', JSON.stringify(JSON.parse(body), null, 2));
  });
});

req.on('error', console.error);
req.write(data);
req.end();
