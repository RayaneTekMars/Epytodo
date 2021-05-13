const express = require('express');
const app = express();
const bodyParser = require('body-parser');

const cookieParser = require('cookie-parser');

const PORT = 8080;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cookieParser())

const router = require('./routes/router');
const { response } = require('express');
app.use('', router);

app.set('view engine', 'ejs');

app.listen(PORT, () => console.log(`Server running on port ${PORT}!`));