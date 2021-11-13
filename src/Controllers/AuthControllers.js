const User = require("../Models/User.model");
const createError = require("http-errors");
const { authSchema } = require("../helpers/validation_schema");
const redis = require("../helpers/init_redis");

const { signAccessToken, signRefreshToken, verifyRefreshToken } = require("../helpers/jwt_helpers");

module.exports = {
  register: async (req, res, next) => {
    try {
      const sanitized = await authSchema.validateAsync(req.body);
      console.log(sanitized);

      const doesExist = await User.findOne({ email: sanitized.email });
      if (doesExist) throw createError.Conflict(`${sanitized.email} is already has been registered`);

      const user = new User(sanitized);
      const savedUser = await user.save();
      const accessToken = await signAccessToken(savedUser.id);
      const refreshToken = await signRefreshToken(savedUser.id);

      res.send({ accessToken, refreshToken });
    } catch (error) {
      if (error.isJoi === true) error.status = 422;
      next(error);
    }
  },
  login: async (req, res, next) => {
    try {
      const sanitized = await authSchema.validateAsync(req.body);
      const user = await User.findOne({ email: sanitized.email });
      if (!user) throw createError.NotFound("User not registered");

      const isMatch = await user.isValidPassword(sanitized.password);
      if (!isMatch) throw createError.Unauthorized("Username/Password not valid");
      const accessToken = await signAccessToken(user.id);
      const refreshToken = await signRefreshToken(user.id);
      res.send({ accessToken, refreshToken });
    } catch (error) {
      if (error.isJoi === true) return next(createError.BadRequest("Invalid Username/Password"));
      next(error);
    }
  },
  refreshToken: async (req, res, next) => {
    try {
      const { refreshToken: refToken } = req.body;
      if (!refToken) throw createError.BadRequest();
      const userId = await verifyRefreshToken(refToken);

      const accessToken = await signAccessToken(userId);
      const refreshToken = await signRefreshToken(userId);
      res.send({ accessToken, refreshToken });
    } catch (error) {
      next(error);
    }
  },
  logout: async (req, res, next) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) throw createError.BadRequest();
      const userId = await verifyRefreshToken(refreshToken);
      redis.DEL(userId, (err, val) => {
        if (err) {
          console.log(err.message);
          throw createError.InternalServerError();
        }
        console.log(val);
        res.sendStatus(204);
      });
    } catch (error) {
      next(error);
    }
  },
};
