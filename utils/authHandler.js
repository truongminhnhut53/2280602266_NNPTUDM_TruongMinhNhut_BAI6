let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

// RS256: dung cap khoa RSA 2048-bit
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '../public.key'), 'utf8')
const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '../private.key'), 'utf8')

module.exports = {
    PRIVATE_KEY,
    PUBLIC_KEY,
    CheckLogin: async function (req, res, next) {
        try {
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
                res.status(401).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let token = req.headers.authorization.split(" ")[1];
            // Verify bang public key, thuat toan RS256
            let result = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] })
            if (result.exp * 1000 < Date.now()) {
                res.status(401).send({
                    message: "token da het han"
                })
                return;
            }
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(401).send({
                    message: "nguoi dung khong ton tai"
                })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(401).send({
                message: "ban chua dang nhap hoac token khong hop le"
            })
        }

    }
}