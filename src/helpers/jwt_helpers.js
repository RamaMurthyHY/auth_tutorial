const JWT = require("jsonwebtoken");
const createError = require("http-errors");
const redis = require("../helpers/init_redis");

module.exports = {
  signAccessToken: (userId) => {
    return new Promise((resolve, reject) => {
      const payload = {};
      const secret = process.env.ACCESS_TOKEN_SECRETE;
      const options = {
        expiresIn: "20s",
        issuer: "pickurpage.com",
        audience: userId,
      };

      JWT.sign(payload, secret, options, (err, token) => {
        if (err) {
          console.log(err.message);
          reject(createError.InternalServerError());
        }
        resolve(token);
      });
    });
  },
  verifyAccessToken: (req, res, next) => {
    if (!req.headers["authorization"]) return next(createError.Unauthorized());
    const authHeader = req.headers["authorization"];
    const bearerToken = authHeader.split(" ");
    const token = bearerToken[1];
    JWT.verify(token, process.env.ACCESS_TOKEN_SECRETE, (err, payload) => {
      if (err) {
        if (err.name === "JsonWebTokenError") return next(createError.Unauthorized());
        return next(createError.Unauthorized(err.message));
      }
      req.payload = payload;
      next();
    });
  },
  signRefreshToken: (userId) => {
    return new Promise((resolve, reject) => {
      const payload = {};
      const secret = process.env.REFRESH_TOKEN_SECRETE;
      const options = {
        expiresIn: "1y",
        issuer: "pickurpage.com",
        audience: userId,
      };

      JWT.sign(payload, secret, options, (err, token) => {
        if (err) {
          reject(createError.InternalServerError());
        }
        const REDIS_KEY_EXPIRY = 360 * 24 * 60 * 60;
        redis.SET(userId, token, "EX", REDIS_KEY_EXPIRY, (err, reply) => {
          if (err) {
            console.log(err.message);
            reject(createError.InternalServerError());
            return;
          }
          resolve(token);
        });
      });
    });
  },
  verifyRefreshToken: (refreshToken) => {
    return new Promise((resolve, reject) => {
      JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRETE, (err, payload) => {
        if (err) return reject(createError.Unauthorized());
        const userId = payload.aud;
        redis.GET(userId, (err, result) => {
          if (err) {
            console.log(err.message);
            reject(createError.InternalServerError());
            return;
          }
          if (refreshToken !== result) reject(createError.Unauthorized());
          return resolve(userId);
        });
      });
    });
  },
};
