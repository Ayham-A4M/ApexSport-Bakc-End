const jwt = require('jsonwebtoken');
const UserModel = require('../models/UserModal')
const verifyAdimin = (req, res, next) => {
    const token = req.cookies.JWT;
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, async (err, decode) => {
        try {
            if (err) { return res.status(401).send({ msg: 'token revoked' }) }
            if (decode.Role === "Admin") {
                const validAdmin = await UserModel.findById(decode.ID);
                if (validAdmin?.TokenVersion === decode.TokenVersion) {
                    res.locals.id = decode.ID;
                    return next();
                }
            }
            return res.status(403).send({ msg: 'Request Blocked' });
        } catch (err) {
            return res.status(401).send(err);
        }
    })
}
module.exports = verifyAdimin;