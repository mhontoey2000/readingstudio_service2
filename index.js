const http = require('http');
const { env } = require('process');
const server = http.createServer((req, res) => {
  console.log("Hello World");
  res.end('Hello World')
});
const PORT = process.env.PORT || 8000
server.listen(PORT, () => console.log("Listening"));