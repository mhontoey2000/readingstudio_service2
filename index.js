const express = require('express')
const app = express()
const { env } = require('process');

const PORT = process.env.PORT || 8000

app.get('/', (req, res) => {
  console.log('Hello World2');
});

app.listen(PORT, () => {
  console.log(`Server is running on port : ${PORT}`)
})