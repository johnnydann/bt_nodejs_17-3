var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
let userSchema = require('../models/users');
const { check_authentication, check_authorization } = require('../Utils/check_auth');
const constants = require('../Utils/constants');
const bcrypt = require('bcrypt');

router.post('/signup', async function(req, res, next) {
    try {
        let body = req.body;
        let result = await userController.createUser(
          body.username,
          body.password,
          body.email,
         'user'
        )
        res.status(200).send({
          success:true,
          data:result
        })
      } catch (error) {
        next(error);
      }
})

router.post('/login', async function(req, res, next) {
    try {
        let username = req.body.username;
        let password = req.body.password;
        let result = await userController.checkLogin(username,password);
        res.status(200).send({
            success:true,
            data:result
        })
      } catch (error) {
        next(error);
      }
})

router.get('/me', check_authentication, async function(req, res, next){
    try {
      res.status(200).send({
        success:true,
        data:req.user
    })
    } catch (error) {
        next();
    }
})

// Route to reset user password to "123456" (admin only)
router.get('/resetPassword/:id', check_authentication, check_authorization(constants.ADMIN_PERMISSION), async function(req, res, next) {
    try {
        const userId = req.params.id;
        const user = await userSchema.findById(userId);
        
        if (!user) {
            throw new Error("User not found");
        }
        
        // Reset password to "123456"
        user.password = "123456";
        await user.save(); // The pre-save hook will hash the password
        
        res.status(200).send({
            success: true,
            message: "Password has been reset to 123456"
        });
    } catch (error) {
        next(error);
    }
});

// Route for users to change their password
router.post('/changePassword', check_authentication, async function(req, res, next) {
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            throw new Error("Current password and new password are required");
        }
        
        // Get user from DB to ensure we have the latest data
        const user = await userSchema.findById(req.user._id);
        
        // Check if current password matches
        if (!bcrypt.compareSync(currentPassword, user.password)) {
            throw new Error("Current password is incorrect");
        }
        
        // Set new password and save
        user.password = newPassword;
        await user.save(); // The pre-save hook will hash the password
        
        res.status(200).send({
            success: true,
            message: "Password changed successfully"
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router