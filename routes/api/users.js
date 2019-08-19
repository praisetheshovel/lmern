const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

// User Model
const User = require('../../models/User');

// @route   POST api/users
// @desc    Register new user
// @access  Public
router.post('/', (req, res) => {
  const { name, email, password } = req.body;

  // FIeld Validation
  if (!name || !email || !password) {
    res.status(400).json({ msg: 'Please enter all fields' });
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

      // Hashing user password to be stored in database
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser.save().then(user => {
            res.json({
              user: {
                id: user.id,
                user: user.name,
                email: user.email
              }
            });
          });
        });
      });
    })
    .catch();
});

module.exports = router;
