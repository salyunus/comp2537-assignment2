/* Loading .env file */
require("dotenv").config();

/* Importing dependencies */
const express = require("express");
const session = require("express-session");
const { default: MongoStore } = require("connect-mongo");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const path = require("path");

/* Creating virtual server and port */
const app = express();
const port = process.env.PORT || 3000;

app.set("view engine", "ejs");

/* Fetching mongoDB information from .env file */
const mongoUser = encodeURIComponent(process.env.MONGODB_USER);
const mongoPassword = encodeURIComponent(process.env.MONGODB_PASSWORD);
const mongoHost = process.env.MONGODB_HOST;
const mongoDatabase = process.env.MONGODB_DATABASE;

/* Building MongoDB connection */
const mongoURL =
  `mongodb+srv://${mongoUser}:${mongoPassword}` +
  `@${mongoHost}/${mongoDatabase}`;

const client = new MongoClient(mongoURL);

let userCollection;

/* Connect to MongoDB and prepare the users collection. */
async function connectToDatabase() {
  await client.connect();

  const db = client.db(mongoDatabase);
  userCollection = db.collection("users");

  await userCollection.createIndex({ email: 1 }, { unique: true });

  console.log("Connected to MongoDB");
}

/* Allow express to read form data from POST requests. */
app.use(express.urlencoded({ extended: false }));

/* Serve static files, including images, from the public folder. */
app.use(express.static(path.join(__dirname, "public")));

/* Configure login sessions.
   Sessions are stored in MongoDB & expire after 1 hour.*/
app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
      mongoUrl: mongoURL,
      dbName: mongoDatabase,
      collectionName: "sessions",
      crypto: {
        secret: process.env.MONGODB_SESSION_SECRET,
      },
      ttl: 60 * 60,
    }),
    cookie: {
      maxAge: 1000 * 60 * 60,
    },
    resave: false,
    saveUninitialized: false,
  }),
);

/* A middleware to check whether the user has a valid logged-in session */
function sessionValidation(req, res, next) {
  if (!req.session || !req.session.authenticated) {
    res.redirect("/login");
    return;
  }

  next();
}

/* A middleware that only allows an admin user to continue. */
async function requireAdmin(req, res, next) {
  const currentUser = await userCollection.findOne({
    email: req.session.email,
  });

  if (!currentUser) {
    req.session.destroy(function () {
      res.clearCookie("connect.sid");
      res.redirect("/login");
    });

    return;
  }
  req.session.userType = currentUser.user_type || "user";

  if (currentUser.user_type !== "admin") {
    res.status(403).render("app", {
      title: "403",
      user: req.session,
      message:
        "You are logged in, but you are not authorized to view the admin page.",
    });

    return;
  }

  next();
}

/* Displays the home page. */
app.get("/", function (req, res) {
  res.render("app", {
    title: "Home",
    user: req.session,
    message: null,
  });
});

/* Displays the signup form. */
app.get("/signup", function (req, res) {
  res.render("signup", {
    title: "Sign up",
    user: req.session,
    message: null,
  });
});

/* POST request for the signup page. Validates input. */
app.post("/signup", async function (req, res) {
  const schema = Joi.object({
    name: Joi.string().trim().max(50).required(),

    email: Joi.string().trim().email().max(100).required(),

    password: Joi.string().max(100).required(),
  });

  const validationResult = schema.validate(req.body);

  if (validationResult.error) {
    res.status(400).render("signup", {
      title: "400",
      user: req.session,
      message: "Please provide a valid name, email, and password.",
    });

    return;
  }

  const name = validationResult.value.name;
  const email = validationResult.value.email.toLowerCase();
  const password = validationResult.value.password;

  const existingUser = await userCollection.findOne({
    email: email,
  });

  if (existingUser) {
    res.status(400).render("signup", {
      title: "400",
      user: req.session,
      message: "An account with this email already exists. Please try again.",
    });

    return;
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.userType = "user";

  res.redirect("/members");
});

/* Get request for the login page. */
app.get("/login", function (req, res) {
  res.render("login", {
    title: "Log in",
    user: req.session,
    message: null,
  });
});

/* POST request for the login page. Validates input. */
app.post("/login", async function (req, res) {
  const schema = Joi.object({
    email: Joi.string().trim().email().max(100).required(),

    password: Joi.string().max(100).required(),
  });

  const validationResult = schema.validate(req.body);

  if (validationResult.error) {
    res.status(401).render("login", {
      title: "401",
      user: req.session,
      message: "Incorrect email or password format. Please Try again.",
    });

    return;
  }

  const email = validationResult.value.email.toLowerCase();
  const password = validationResult.value.password;

  const user = await userCollection.findOne({
    email: email,
  });

  if (!user) {
    res.status(401).render("login", {
      title: "401",
      user: req.session,
      message: "Invalid email/password combination. Please Try again.",
    });

    return;
  }

  const passwordMatches = await bcrypt.compare(password, user.password);

  if (!passwordMatches) {
    res.status(401).render("login", {
      title: "401",
      user: req.session,
      message: "Invalid password. Please Try again.",
    });

    return;
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;
  req.session.userType = user.user_type || "user";

  res.redirect("/members");
});

/* Get request for admin page */
app.get("/admin", sessionValidation, requireAdmin, async function (req, res) {
  const users = await userCollection.find({}).sort({ email: 1 }).toArray();

  res.render("admin", {
    title: "Admin",
    user: req.session,
    users: users,
  });
});

/* Promote a user to admin */
app.post(
  "/admin/promote/:id",
  sessionValidation,
  requireAdmin,
  async function (req, res) {
    const schema = Joi.string().hex().length(24).required();

    const validationResult = schema.validate(req.params.id);

    if (validationResult.error) {
      res.status(400).render("404", {
        title: "Invalid user.",
        user: req.session,
      });

      return;
    }

    await userCollection.updateOne(
      {
        _id: new ObjectId(req.params.id),
      },
      {
        $set: {
          user_type: "admin",
        },
      },
    );

    res.redirect("/admin");
  },
);

/* Demote an admin to user */
app.post(
  "/admin/demote/:id",
  sessionValidation,
  requireAdmin,
  async function (req, res) {
    const schema = Joi.string().hex().length(24).required();

    const validationResult = schema.validate(req.params.id);

    if (validationResult.error) {
      res.status(400).render("404", {
        title: "Invalid user.",
        user: req.session,
      });

      return;
    }

    await userCollection.updateOne(
      {
        _id: new ObjectId(req.params.id),
      },
      {
        $set: {
          user_type: "user",
        },
      },
    );

    const demotedUser = await userCollection.findOne({
      _id: new ObjectId(req.params.id),
    });

    if (demotedUser && demotedUser.email === req.session.email) {
      req.session.userType = "user";

      req.session.save(function () {
        res.redirect("/admin");
      });

      return;
    }

    res.redirect("/admin");
  },
);

/* Get request for members page. */
app.get("/members", sessionValidation, function (req, res) {
  const images = [
    "/images/image1.jpg",
    "/images/image2.jpg",
    "/images/image3.jpg",
  ];

  res.render("members", {
    title: "Members",
    user: req.session,
    images: images,
  });
});

/* Discards the session and returns the user to the home page. */
app.get("/logout", function (req, res) {
  req.session.destroy(function () {
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

/* Catch all routes that were not defined above. */
app.use(function (req, res) {
  res.status(404).render("404", {
    title: "404",
    user: req.session,
  });
});

/* Starts the server after MongoDB successfully connects. */
connectToDatabase()
  .then(function () {
    app.listen(port, function () {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch(function (error) {
    console.error(error);
  });
