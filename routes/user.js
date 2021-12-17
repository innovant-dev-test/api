const express = require("express");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();
const auth = require("../middleware/auth");
const User = require("../model/User");
const config = require("config");



router.post(
  "/register",
  async (req, res) => {
    const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { email, password } = req.body;
  try {
    let existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(400)
        .json({ errors: [{ msg: "Email already used !" }] });
    } else {
      const salt = await bcrypt.genSalt(10);
      var user = new User();
      user.username=req.body.firstname+" "+req.body.lastname;
      user.email = req.body.email;
      user.password = await bcrypt.hash(req.body.password, salt);
      try {
        await user.save();
        res.send("user added");
      } catch (err) {
        console.error(err);
      }
    }
  } catch (err) {
    res.status(500).send("Server error");
  }
  }
);

router.post(
  "/login",
  async (req, res) => {
    check("email", "Please include a valid email").isEmail();
  check("password", "Password is required").exists();
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ errors: [{ msg: "Invalid Credentials" }] });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ errors: [{ msg: "Invalid Credentials" }] });
    }

    const payload = {
      user: {
        id: user.id,
        email: user.email,
      },
    };

    jwt.sign(
      payload,
      config.get("jwtSecret"),
      { expiresIn: "5 days" },
      (err, token) => {
        if (err) throw err;
        res.json({ token, user });
        res.sendStatus(200)
        
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }

    
  }
);

module.exports = router;
