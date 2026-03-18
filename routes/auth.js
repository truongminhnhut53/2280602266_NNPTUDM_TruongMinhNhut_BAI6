var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let { body, validationResult } = require('express-validator')
const { CheckLogin, PRIVATE_KEY, PUBLIC_KEY } = require("../utils/authHandler");

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, "69b0ddec842e41e8160132b8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send(error.message)
    }

})

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(403).send({
                message: "ban dang bi ban"
            })
            return
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            // Ky token bang private key, thuat toan RS256 (2048-bit RSA)
            let token = jwt.sign(
                { id: user._id },
                PRIVATE_KEY,
                {
                    algorithm: 'RS256',
                    expiresIn: '1h'
                }
            )
            res.send({ token })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }

})

router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user)
})

// ============================================================
// CHANGE PASSWORD - Yeu cau dang nhap (CheckLogin middleware)
// POST /api/v1/auth/change-password
// Body: { oldPassword, newPassword }
// ============================================================
const changePasswordValidator = [
    body('oldPassword')
        .notEmpty().withMessage('Mat khau cu khong duoc de trong'),

    body('newPassword')
        .notEmpty().withMessage('Mat khau moi khong duoc de trong')
        .bail()
        .isLength({ min: 8 }).withMessage('Mat khau moi phai co it nhat 8 ky tu')
        .bail()
        .matches(/[A-Z]/).withMessage('Mat khau moi phai co it nhat 1 chu hoa')
        .bail()
        .matches(/[a-z]/).withMessage('Mat khau moi phai co it nhat 1 chu thuong')
        .bail()
        .matches(/[0-9]/).withMessage('Mat khau moi phai co it nhat 1 chu so')
        .bail()
        .matches(/[^A-Za-z0-9]/).withMessage('Mat khau moi phai co it nhat 1 ky tu dac biet')
]

router.post('/change-password',
    CheckLogin,
    changePasswordValidator,
    async function (req, res, next) {
        // Kiem tra validate errors
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).send({
                message: 'Du lieu khong hop le',
                errors: errors.array().map(e => ({ [e.path]: e.msg }))
            })
        }

        try {
            let { oldPassword, newPassword } = req.body;
            let user = req.user; // Lay tu CheckLogin middleware

            // Kiem tra mat khau cu co dung khong
            let isMatch = bcrypt.compareSync(oldPassword, user.password)
            if (!isMatch) {
                return res.status(400).send({
                    message: 'Mat khau cu khong chinh xac'
                })
            }

            // Kiem tra mat khau moi khac mat khau cu
            if (oldPassword === newPassword) {
                return res.status(400).send({
                    message: 'Mat khau moi phai khac mat khau cu'
                })
            }

            // Cap nhat mat khau moi (schema se tu dong bcrypt qua pre-save hook)
            user.password = newPassword;
            await user.save()

            res.send({
                message: 'Doi mat khau thanh cong'
            })
        } catch (error) {
            res.status(500).send({
                message: error.message
            })
        }
    }
)

module.exports = router;