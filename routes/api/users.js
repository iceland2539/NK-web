const express = require("express");
const router = express.Router();
const { check, validationResult } = require("express-validator");

const bcrypt = require("bcryptjs");
const User = require("../../models/User.js");
const jwt = require("jsonwebtoken");
const config = require("config");
const gravatar = require("gravatar");

//@route POST api/users
//@desc Register User @ get token
//@access Public

router.post(
  "/",
  [
    check("name", "Name is require").notEmpty(),
    check("email", "Please include email").isEmail(),
    check(
      "password",
      "Please enter password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ erros: errors.array() });
    }

    // Front end  pass data to api
    const { name, email, password } = req.body;

    try {
      // See if user exits
      let user = await User.findOne({ email });
      if (user) {
        res.status(400).json({ errors: [{ msg: "User already extis" }] });
      }

      // Get gravatar
      const avatar = gravatar.url(email, {
        s: "200",
        r: "pg",
        d: "mm",
      });
      user = new User({
        name,
        email,
        avatar,
        password,
      });

      // Encrypt password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save();

      // Return jsonwebtoken
      const payload = {
        user: {
          id: user.id,
        },
      };
      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 36000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.log(err.message);
      res.status(500).send("Server Error");
    }
  }
);

module.exports = router;
