//<!--===============================================================================================-->
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
//<!--===============================================================================================-->
router.post('/register', userController.register);
router.post('/login', userController.login);
router.post('/auth', userController.auth);
router.post('/logout', userController.logout);
router.post('/redirect', userController.redirect);
//<!--===============================================================================================-->
module.exports = router
//<!--===============================================================================================-->