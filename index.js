const express = require('express')
const app = express()
const mysql = require('mysql2');
const { env } = require('process');

const PORT = process.env.PORT || 8000

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD
});

connection.connect((err) => {
  if (!!err) {
    console.log(err);
  } else {
    console.log('Connected...');
  }

});

app.get('/', (req, res) => {
  console.log('Hello World2');
  res.json("hello world2222")
});

app.listen(PORT, () => {
  console.log(`Server is running on port : ${PORT}`)
})