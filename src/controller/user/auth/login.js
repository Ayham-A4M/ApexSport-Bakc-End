const userModel = require('../../../models/UserModal')
const { validationResult } = require('express-validator');
const bcrybt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const login = (req, res) => {


    const resultValidation = validationResult(req);
    if (!resultValidation.isEmpty()) { return res.status(404).send({ msg: resultValidation.errors[0].msg }); }
    const userInfo = req.body;
    userModel.findOne({ Email: userInfo.Email }).then((user) => {
        if (user === null || user === undefined) { return res.status(404).send({ msg: "email or password is wrong" }); }

        if (user) {
            bcrybt.compare(userInfo.password, user.password).then((response) => {
                if (!response) { return res.status(404).send({ msg: "email or password is wrong" }) }
                else {
                    // const Payload = { FirstName: user.FirstName, LastName: user.LastName, Email: user.Email, UserName: user.UserName, Role: user.Role, ID: user._id };
                    const Payload = { UserName: user.UserName, Role: user.Role, ID: user._id, Email: user.Email, FirstName: user.FirstName, LastName: user.LastName, TokenVersion: user.TokenVersion };
                    const accessToken = jwt.sign(Payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
                    const refreshToken = jwt.sign(Payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
                    res.cookie('JWT', accessToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 15 * 60 * 1000 });
                    res.cookie('RefreshToken', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
                    return res.status(201).send({ msg: 'logged in successfully', User: Payload });
                }
            }).catch((err) => {
                res.status(400).send({ msg: 'server error' });

            })
        }
    })
}
module.exports = login