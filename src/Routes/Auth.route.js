const express = require("express");
const router = express.Router();
const AuthControllers = require("../Controllers/AuthControllers");

router.post("/register", AuthControllers.register);
router.post("/login", AuthControllers.login);
router.post("/refresh-token", AuthControllers.refreshToken);
router.delete("/logout", AuthControllers.logout);

module.exports = router;
