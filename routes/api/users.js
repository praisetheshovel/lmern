const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');

// User Model
const User = require('../../models/User');

// @route   POST api/users
// @desc    Register new user
// @access  Public
router.post('/', (req, res) => {
  const { name, email, password } = req.body;

  // Field Validation
  if (!name || !email || !password) {
    return res.status(400).json({ msg: 'Please enter all fields' });
  }

  // Check existing error
  User.findOne({ email })
    .then(user => {
      // If user exists
      if (user) return res.status(400).json({ msg: 'User already exists' });

      // else create a newUser
      const newUser = new User({
        name,
        email,
        password
      });

      // Create salt & hash -- Hashing user password to be stored in database
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          // save() -- saves to MongoDB -- already makes sure that the id_ is not repeated
          newUser.save().then(user => {
            // sign() : first parameter = payload -- second parameter = secret -- optional paramaters in JSON format
            jwt.sign(
              { id: user.id },
              config.get('jwtSecret'),
              { expiresIn: 3600 },
              (err, token) => {
                if (err) throw err;
                res.json({
                  token: token,
                  user: {
                    id: user.id,
                    name: user.name,
                    email: user.email
                  }
                });
              }
            );
          });
        });
      });
    })
    .catch();
});

module.exports = router;
