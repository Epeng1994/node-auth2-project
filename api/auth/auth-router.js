const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const {add} = require('../users/users-model')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  add({...req.body, role_name: req.role_name})
    .then(result=>res.status(201).json(result))
    .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  const {password} = req.body
  if(bcrypt.compareSync(password, req.user.password) ==false){ //bcrypt.compareSync
    next({status:401,message:"Invalid credentials"})
    return
  }else{
    const token = generateToken(req.user)
    res.json({message: `${req.user.username} is back!`, token: token})
  }
});

function generateToken({user_id,username,role_name}){
  const payload = {
    subject  : user_id, // the user_id of the authenticated user
    role_name: role_name,   // the role of the authenticated user    
    username : username  // the username of the authenticated user
  }
  const options = {
    expiresIn : "1d"
  }
  return jwt.sign(payload, JWT_SECRET, options)
}


module.exports = router;
