const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const createHttpError = require('http-errors');
const User = require('../model/User');
const rolesList = require('../config/rolesList');
const dotenv = require('dotenv');

dotenv.config();

const handleAuth = async (req, res, next) => {
    try {
        const cookies = req.cookies;
        const { username, password } = req.body;

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
            const roles = Object.values(foundUser.roles).filter(Boolean);
            const accessToken = jwt.sign(
                {
                    userInfo: {
                        username: foundUser.username,
                        userRoles: roles,
                    },
                    serverInfo: {
                        serverRolesList: rolesList,
                    },
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '10m' }
            );
            const newRefreshToken = jwt.sign(
                {
                    username: foundUser.username,
                },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: '1d' }
            );
            let newRefreshTokenArray = !cookies?.jwt
                ? foundUser.refreshToken
                : foundUser.refreshToken.filter(item => item !== cookies.jwt);
            if (cookies?.jwt) {
                const refreshToken = cookies.jwt;
                const foundToken = await User.findOne({
                    refreshToken,
                }).exec();

                //Detected refresh token reuse
                if (!foundToken) {
                    newRefreshTokenArray = [];
                }
                res.clearCookie('jwt', {
                    httpOnly: true,
                    sameSite: 'None',
                    secure: true,
                });
            }

            //Saving refresh token with foundUser
            foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
            await foundUser.save();

            //Create secure cookie with refresh token
            res.cookie('jwt', newRefreshToken, {
                httpOnly: true,
                sameSite: 'None',
                secure: true, //Change to [false] when testing with Thunder Client
                maxAge: 24 * 60 * 60 * 1000,
            });

            res.status(200).json({ accessToken });
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
