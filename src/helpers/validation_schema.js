const Joi = require("@hapi/joi");
const createError = require("http-errors");

const authSchema = Joi.object({
  email: Joi.string().email().lowercase().required(),
  // .error((errors) => {
  //   errors.forEach((err) => {
  //     switch (err.code) {
  //       case "string.email":
  //         throw createError.BadRequest("email is not a valid");
  //       case "any.required":
  //         throw createError.BadRequest("email is required very badly");
  //     }
  //   });
  //   return errors;
  // }),
  password: Joi.string().min(2).required(),
});

module.exports = {
  authSchema,
};
