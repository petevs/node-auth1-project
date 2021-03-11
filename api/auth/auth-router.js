// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const bcrypt = require('bcryptjs')
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require('./auth-middleware')
const router = express.Router()
const users = require('../users/users-model')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/register', checkUsernameFree(), checkPasswordLength(), async (req, res, next) => {
  try {
    const { username, password } = req.body
    const newUser = await users.add({
      username,
      password: await bcrypt.hash(password, 1)
    })
    res.status(201).json(newUser)

  } catch(err) {
    next(err)
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

 router.post('/login', checkUsernameExists(),async ( req, res, next) => {
    try{
      const { username, password } = req.body
      const user = await users.findBy({ username }).first()

      //need to hash password to check
      const passwordValid = await bcrypt.compare(password, user.password)

      if(!passwordValid){
       return res.status(401).json({
          message: 'Invalid credentials'
        })
      }

      req.session.user = user

      res.status(200).json({
        message: `Welcome ${user.username}!`
      })

    } catch(err){
        next(err)
    }
 })

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 router.get('/logout', async (req, res, next) => {
   try {
      if(!req.session.user){
       return res.status(200).json({
         message: "no session"
       })
     }

     req.session.destroy((err) => {
       if (err) {
         return res.status(200).json({
           message: "no session"
         })
       } 
       else {
         res.status(200).json({
           message: 'logged out'
         })
       }
     })
   } catch(err){
     next(err)
   }
 })
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router