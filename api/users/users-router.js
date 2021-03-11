// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const express = require("express")
const users = require('./users-model')
const { restricted } = require('../auth/auth-middleware')

const router = express.Router()
/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */


// Don't forget to add the router to the `exports` object so it can be required in other modules

router.get('/users', restricted(), async ( req, res, next) => {
  try{
    const results = await users.find()
    res.json(results)
  } 
  catch(err) {
      next(err)
  }
})

module.exports = router