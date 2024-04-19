const express = require('express');

const app = express();

app.use('/static', express.static('static'))

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JS safe</title>
<link rel="stylesheet" href="/static/safe.css">
</head>
<body>
<div class="title">
<h1>JS Safe!</h1>
</div>
<div class="numpad-container">
  <div id="display"></div>
  <div class="numpad">
    <button onclick="addToPassword(1)">1</button>
    <button onclick="addToPassword(2)">2</button>
    <button onclick="addToPassword(3)">3</button>
    <button onclick="addToPassword(4)">4</button>
    <button onclick="addToPassword(5)">5</button>
    <button onclick="addToPassword(6)">6</button>
    <button onclick="addToPassword(7)">7</button>
    <button onclick="addToPassword(8)">8</button>
    <button onclick="addToPassword(9)">9</button>
    <button onclick="clearPassword()">Clear</button>
    <button onclick="addToPassword(0)">0</button>
    <button onclick="deletePassword()">Delete</button>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js"></script>
<script src="/static/safe.js"></script>
</body>
</html>
    `);
});

app.listen(5000, () => {
    console.log('Server is running on port 5000');
});

