var express = require('express');
var router = express.Router();
let userSchema = require('../models/users');
let userController = require('../controllers/users')
let BuildQueries = require('../Utils/BuildQuery');
let {check_authentication,
  check_authorization} = require('../Utils/check_auth')
let constants = require('../Utils/constants')

router.get('/', async function(req, res, next) {
  let queries = req.query;
  let users = await userSchema.find(BuildQueries.QueryUser(queries)).populate('role');
  res.send(users);
});

router.get('/:id',check_authentication, async function(req, res, next) {
  try {
    if(req.user._id==req.params.id){
      let user = await userSchema.findById(req.params.id).populate('role');
      res.status(200).send({
        success: true,
        data: user
      });
    }else{
      throw new Error("ban khong co quyen")
    } 
  } catch (error) {
    next(error)
  }
});

router.post('/',check_authentication,
check_authorization(constants.MOD_PERMISSION),async function(req, res, next) {
  try {
    let body = req.body;
        let result = await userController.createUser(
          body.username,
          body.password,
          body.email,
          body.role
        )
        res.status(200).send({
          success:true,
          data:result
        })
  } catch (error) {
    next(error);
  }
  
});

router.put('/:id', async function(req, res, next) {
  try {
    let body = req.body;
    let user = await userSchema.findById(
      req.params.id
    ).populate({
      path:"role",select:"roleName"
    });
    if(user){
      let allowField=["password","email","fullName","avatarUrl"];
      for (const key of Object.keys(body)) {
        if(allowField.includes(key)){
          user[key] = body[key]
        }
      }
      await user.save();
      res.status(200).send({
        success: true,
        data: user
      });
    }  
  } catch (error) {
    next(error)
  }
});

module.exports = router;