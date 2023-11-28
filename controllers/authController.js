const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const createHttpError = require('http-errors');
const User = require('../model/User');
const rolesList = require('../config/rolesList');
const dotenv = require('dotenv');

dotenv.config();

const handleAuth = async (req, res, next) => {
    try {
        const { username, password, token } = req.body;

        //Check for required fields
        if (!username || !password)
            throw createHttpError(400, 'Dados pendentes');

        //Check for user in db
        const foundUser = await User.findOne({ username }).exec();
        if (!foundUser)
            throw createHttpError(
                401,
                'Usuário e/ou senha não identificado(s)'
            );

        //Evaluate password
        const match = await bcrypt.compare(password, foundUser.password);
        if (match) {
            if (token) {
                foundUser.refreshToken === token;
            } else {
                //Saving refresh token with foundUser
                foundUser.refreshToken = generateAuthToken(foundUser.username);
                await foundUser.save();
            }
            res.status(200).json({ userData: foundUser, rolesList: rolesList });
        } else {
            throw createHttpError(401, 'Usuário ou senha não identificado(s).');
        }
    } catch (error) {
        next(error);
    }
};

const generateAuthToken = stringToHash => {
    const token = jwt.sign(stringToHash, process.env.TOKEN_SECRET);
    return token;
};

module.exports = { handleAuth, generateAuthToken };
