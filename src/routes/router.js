const express = require('express');
const router = express.Router();
const app = express();
const fetch = require('node-fetch');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('../config/db');
const middleware = require('../middleware/auth');
const connection = require('../config/db');
const { response } = require('express');

app.set('view engine', 'ejs')

const extractBearerToken = headerValue => {
    if (typeof headerValue !== 'string')
        return false
    const matches = headerValue.match(/(bearer)\s+(\S+)/i)
    return matches && matches[2]
}

const checkToken = (req, res, next) => {
    const token = req.cookies.authcookie && req.headers.authorization && extractBearerToken(req.headers.authorization)
    if (!token)
        return res.status(401).json({ msg: 'No token, authorization denied' });

    jwt.verify(token, process.env.SECRET, (err, decodedToken) => {
        if (err) {
            return res.status(401).json({ msg: 'Token is not valid' });
        } else {
            return next();
        }
    });
}

router.get('/app', (req, res) => {

    console.log(req.cookies);
    console.log(req.signedCookies);

    if (!req.cookies.authcookie) {
        res.render('login.ejs');
    } else {

        res.render('app.ejs', {
            id: 45
        });

    }
});

router.post('/register', middleware.validateRegister, (req, res, next) => {
    let email = req.body.email;
    let pass = req.body.password;
    let name = req.body.name;
    let firstname = req.body.firstname;

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(pass, salt, (err, hash) => {
            if (err)
                return res.status(500).send({ msg: "internal server error" });
            let sql = 'INSERT INTO user SET ?';
            let post = {
                email: email,
                password: hash,
                name: name,
                firstname: firstname
            };
            db.query(sql, post, (err, result) => {
                if (err)
                    return res.status(400).send({ msg: err });
                else {
                    const token = jwt.sign({ email }, process.env.SECRET, { expiresIn: '30 minutes' });
                    return res.status(201).send({ token: token });
                }
            });
        });
    });
});

router.post('/login', middleware.valideLogin, (req, res, next) => {
    let email = req.body.email;
    let pass = req.body.password;

    let sql = 'SELECT password, id FROM user WHERE ?';
    let post = { email: email }
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        let hash_pass = result[0].password;
        let id = result[0].id
        bcrypt.compare(pass, hash_pass, (err, result) => {
            if (err)
                return res.status(500).send({ msg: err });
            if (email) {
                const token = jwt.sign({ email, id }, process.env.SECRET, { expiresIn: '3 hours' });
                res.cookie('authcookie', token, { maxAge: 900000, httpOnly: false })
                if (result == true) {
                    return res.status(201).send({ token: token });
                }
                return res.status(400).send({ msg: 'Invalid Credentials' })
            }
        });
    });
});

router.get('/user', checkToken, (req, res, next) => {
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization)
    const decoded = jwt.decode(token, { complete: false })

    let sql = 'SELECT * FROM user WHERE ?';
    let post = { email: decoded.email };
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else
            return res.status(200).send(result);
    });
});

router.get('/user/todos', checkToken, (req, res, next) => {
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, { complete: false });


    let sql = 'SELECT * FROM todo WHERE ?';
    let post = { user_id: decoded.id };
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else
            return res.status(200).send(result);
    });
});

router.get('/user/:email', checkToken, (req, res, next) => {
    if (!req.params.email.includes('@', 0))
        return next();
    let sql = 'SELECT * FROM user WHERE ?';
    let post = { email: req.params.email };
    connection.query(sql, post, (err, result) => {
        console.log('test')
        if (err)
            return res.status(400).send({ msg: err });
        else
            return res.status(200).send(result);
    });
});

router.get('/user/:id', checkToken, (req, res, next) => {
    let sql = 'SELECT * FROM user WHERE ?'
    let post = { id: req.params.id }
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else
            return res.status(200).send(result);
    });
});

router.put('/user/:id', checkToken, (req, res, next) => {
    let email = req.body.email;
    let pass = req.body.password;
    let name = req.body.name;
    let firstname = req.body.firstname;
    let created_at = req.body.created_at;

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(pass, salt, (err, hash) => {
            if (err)
                return res.status(400).send({ msg: err });
            let sql = `UPDATE user SET ? WHERE id = ${req.params.id}`;
            let post = {
                email: email,
                password: hash,
                name: name,
                firstname: firstname,
                created_at: created_at
            };
            connection.query(sql, post, (err, result) => {
                if (err)
                    return res.status(400).send({ msg: err });
                connection.query(`SELECT * FROM user WHERE id = ${req.params.id}`, (err, result) => {
                    if (err)
                        return res.status(400).send({ msg: err });
                    return res.status(201).send(result);
                });
            });
        });
    });
});

router.delete('/user/:id', checkToken, (req, res, next) => {
    let sql = 'DELETE FROM user WHERE ?';
    let post = { id: req.params.id };
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else if (result.affectedRows == 0)
            return res.status(400).send({ msg: 'This account does not exist.' });
        else
            return res.status(201).send({ msg: `succesfully deleted record number: ${req.params.id}` });
    });
});

router.get('/todo', checkToken, (req, res, next) => {
    connection.query('SELECT * FROM todo', (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else
            return res.status(200).send(result);
    });
});

router.get('/todo/:id', checkToken, (req, res, next) => {
    let sql = 'SELECT * FROM todo WHERE ?';
    let post = { user_id: req.params.id };
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else
            return res.status(200).send(result);
    });
});

router.post('/todo', checkToken, (req, res, next) => {
    let title = req.body.title;
    let description = req.body.description;
    let due_time = req.body.due_time;
    let user_id = req.body.user_id;
    let status = req.body.status;

    let sql = 'INSERT INTO todo SET ?';
    let post = {
        title: title,
        description: description,
        due_time: due_time,
        user_id: user_id,
        status: status
    };

    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else {
            connection.query(`SELECT * FROM todo WHERE user_id = ${user_id} AND title = "${title}"`, (err, result) => {
                if (err)
                    res.status(400).send({ msg: err });
                else
                    res.status(201).send(result);
            });
        }
    });
});

router.put('/todo/:id', checkToken, (req, res, next) => {
    let title = req.body.title;
    let description = req.body.description;
    let due_time = req.body.due_time;
    let user_id = req.body.user_id;
    let status = req.body.status;

    let sql = `UPDATE todo SET ? WHERE id = ${req.params.id}`;
    let post = {
        title: title,
        description: description,
        due_time: due_time,
        user_id: user_id,
        status: status
    };
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ err: msg });
        connection.query(`SELECT * FROM todo WHERE id = ${req.params.id}`, (err, result) => {
            if (err)
                return res.status(400).send({ msg: err });
            return res.status(201).send(result);
        });
    });
});

router.delete('/todo/:id', checkToken, (req, res, next) => {
    let sql = 'DELETE FROM todo WHERE ?'
    let post = { id: req.params.id }
    connection.query(sql, post, (err, result) => {
        if (err)
            return res.status(400).send({ msg: err });
        else if (result.affectedRows == 0)
            return res.status(400).send({ msg: 'This task does not exist.' });
        else
            return res.status(201).send({ msg: `succesfully deleted record number: ${req.params.id}` });
    });
});

module.exports = router;