const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

module.exports = {
    validateRegister: (req, res, next) => {
        if (!req.body.email.includes('@', 0)) {
            return res.status(400).send({ 
                msg: 'Please enter a valid email'
            });
        }

        if (req.body.email.length <= 0) {
            return res.status(400).send({ 
                msg: 'Please enter an email'
            });
        }

        if (req.body.password.length <= 0) {
            return res.status(400).send({
                msg: 'Please enter a password'
            });
        }

        if (req.body.name.length <= 0 || req.body.firstname.length <= 0) {
            return res.status(400).send({
                msg: 'Please enter your name and first name.'
            });
        }

        next();
    },

    valideLogin: (req, res, next) => {
        if (!req.body.email || req.body.email.length < 3) {
            return res.status(400).send({
                msg: 'Email contains at least 3 chars.'
            });
        }

        if (!req.body.password) {
            return res.status(400).send({
                msg: 'Please enter a password.'
            });
        }

        next();
    }
};