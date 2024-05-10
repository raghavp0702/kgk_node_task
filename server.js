const mysql = require('mysql2');
const express = require('express');

const app = express();
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrpyt = require('bcrypt');
app.use(express.json());
const cookieParser = require('cookie-parser');
app.use(cookieParser());

dotenv.config();


//creating database connection with environment variables

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    // password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });
  console.log(process.env.DB_HOST);
  
  db.connect(err => {
    if (err) {
      console.error('Database connection error:', err);
    } else {
      console.log('Connected to MySQL database');
    }
  });

  const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


//register route where user can register and generates jwt refresh and access tokens

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json("Username or Password is required.");
  }
  if (username < 6) {
    return res.json("Enter a username with length greater than 6");
  }
  if (password > 20) {
    return res.json("Enter a password with length less than 20");
  }
  // checking password validation
  const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\W_]).{6,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      error:
        "Password must contain at least 6 characters with atleast 1 uppercase letter, 1 lowercase letter, 1  number, and 1 special character.",
    });
  }

  db.query(
    "Select * From Users Where username = ?",
    [username],
    async (err, data) => {
      if (data.length > 0) {
        return res.json("Username already exists. Choose a new Username");
      }
      if (err) {
        return res.json("Error: ", err);
      }
      const hashPassword = await bcrpyt.hash(password, 10);

      const payload = {
        username,
        hashPassword,
      };

      db.query(
        "Insert into users (username,password,refresh_token) values (?,?,?)",
        [username, password, refreshToken],
        (err, data) => {
          if (err) {
            res.json("Error: ", err);
          }

          const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: "2h",
          });
          const refreshToken = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: "2d",
          });
          res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: true,
            maxAge: 2 * 60 * 60 * 1000,
          });
          res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            maxAge: 2 * 24 * 60 * 60 * 1000,
          });

          res.json({
            message: "User registered Successfully",
            accessToken,
            refreshToken,
          });
        }
      );
    }
  );
});

// login route where user can login with username or password or they can login with their accesstoken or with refresh token and a new accessToken is generated

app.post("/login", async (req, res) => {
  const accessToken = req.cookies?.accessToken;
  const refreshToken = req.cookies?.refreshToken;
  console.log(refreshToken);

  if (accessToken) {
    // if user has access token they can login directly without username and password
    try {
      const accessTokenCheck = jwt.verify(refreshToken, process.env.JWT_SECRET);
      if (accessTokenCheck) {
        res.json({
          messaage: "You are logged in successfully through accessToken",
          accessToken,
        });
      }
    } catch (error) {
      res.json("Error:", error);
    }
  }

  if (!accessToken && refreshToken) {
    // if accesstoken is expired, the refresh token is used to generate a new accessToken and login the user
    try {
      const refreshTokenCheck = jwt.verify(
        refreshToken,
        process.env.JWT_SECRET
      );
      req.user = refreshTokenCheck;
      const { username, password } = req.user;

      const newaccessToken = jwt.sign(
        { username, password },
        process.env.JWT_SECRET,
        {
          expiresIn: "2h",
        }
      );

      res.cookie("accessToken", newaccessToken, {
        httpOnly: true,
        secure: true,
        maxAge: 2 * 60 * 60 * 1000,
      });

      res.json({
        messaage:
          "You are logged in successfully through refreshToken and your new accessToken is generated",
        newaccessToken,
        refreshToken,
      });
    } catch (error) {
      res.json("Error:", error);
    }
  } else {
    // if user does not have either tokens then, they have to login with uesrname and password
    const { username, password } = req.body;

    if (!username || !password) {
      return res.json("Username or Password are required");
    }

    if (username < 6) {
      return res.json("Enter a username with length greater than 6");
    }

    db.query(
      "Select * from users where username = ?",
      [username],
      async (err, data) => {
        if (err) {
          return res.json("Cannot reach database");
        }
        if (data.length === 0) {
          return res.json("Invalid Username or password");
        }

        const user = data[0];

        const isPasswordSame = await bcrpyt.compare(password, user.password);

        if (!isPasswordSame) {
          return res.json("Invalid Password or Username");
        }

        const newaccessToken = jwt.sign(
          { username, password },
          process.env.JWT_SECRET,
          {
            expiresIn: "2h",
          }
        );

        const newrefreshToken = jwt.sign(
          { username, password },
          process.env.JWT_SECRET,
          {
            expiresIn: "2d",
          }
        );

        db.query(
          "Update users Set refresh_token =? WHERE id = ?",
          [refreshToken, user.id],
          async (err) => {
            if (err) {
              res.json("Cannot reach database");
            }
            res.cookie("accessToken", newaccessToken, {
              httpOnly: true,
              secure: true,
              maxAge: 2 * 60 * 60 * 1000,
            });
            res.cookie("refreshToken", newrefreshToken, {
              httpOnly: true,
              secure: true,
              maxAge: 2 * 24 * 60 * 60 * 1000,
            });

            res.json(
              { message: "login successfull" },
              newaccessToken,
              newrefreshToken
            );
          }
        );
      }
    );
  }
});

//middleware to verify accesstoken

function verifyAccessToken(req, res, next) {
  const accessToken = req.cookies.accessToken;
  const refreshToken = req.cookies.refreshToken;

  if (!accessToken) {
    // if they do have refresh token, we verify it and generate a new one while accessing dashboard route
    try {
      const refreshTokenCheck = jwt.verify(
        refreshToken,
        process.env.JWT_SECRET
      );
      req.user = refreshTokenCheck;
      const { username, password } = req.user;

      const accessToken = jwt.sign(
        { username, password },
        process.env.JWT_SECRET,
        {
          expiresIn: "2h",
        }
      );

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: 2 * 60 * 60 * 1000,
      });

      next();
    } catch (error) {
      res.json("Error: while accessing access token", error);
    }
  } else {
    try {
      const tokenCheck = jwt.verify(accessToken, process.env.JWT_SECRET);

      req.user = tokenCheck;
      next();
    } catch (error) {
      res.json("Please login again with correct credentials");
    }
  }
}

// logout route to remove all the tokens from cookies and logout the user

app.post("/logout", (req, res) => {
  res.clearCookie("accessToken", { httpOnly: true, secure: true });
  res.clearCookie("refreshToken", { httpOnly: true, secure: true });

  res.json({ message: "You have logged out successsfully" });
});

// dashboard route to check is user is authorized and then only they are welcomed

app.get("/dashboard", verifyAccessToken, async (req, res) => {
  const { username } = req.user;

  res.json({ message: "Welcome to Dashboard ", username });
});


