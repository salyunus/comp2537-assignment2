/* Loading .env file */
require('dotenv').config();

/* Importing dependencies */
const express = require("express");
const session = require("express-session");
const { default: MongoStore } = require("connect-mongo");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const path = require("path");

/* Creating virtual server and port */
const app = express();
const port = process.env.PORT || 3000;

/* Fetching mongoDB information from .env file */
const mongoUser = encodeURIComponent(process.env.MONGODB_USER);
const mongoPassword = encodeURIComponent(process.env.MONGODB_PASSWORD);
const mongoHost = process.env.MONGODB_HOST;
const mongoDatabase = process.env.MONGODB_DATABASE;

/* Building MongoDB connection */
const mongoURL = `mongodb+srv://${mongoUser}:${mongoPassword}` +
                 `@${mongoHost}/${mongoDatabase}`;

const client = new MongoClient(mongoURL);

let userCollection;

/* Connect to MongoDB and prepare the users collection. */
async function connectToDatabase()
{
    await client.connect();

    const db = client.db(mongoDatabase);
    userCollection = db.collection("users");

    await userCollection.createIndex(
        { email: 1 },
        { unique: true }
    );

    console.log("Connected to MongoDB");
};

/* Allow express to read form data from POST requests. */
app.use(express.urlencoded({ extended: false }));

/* Serve static files, including images, from the public folder. */
app.use(express.static(path.join(__dirname, "public")));

/* Configure login sessions.
   Sessions are stored in MongoDB & expire after 1 hour.*/
app.use(session(
    {
        secret: process.env.NODE_SESSION_SECRET,
        store: MongoStore.create(
            {
                mongoUrl: mongoURL,
                dbName: mongoDatabase,
                collectionName: "sessions",
                crypto: {
                    secret: process.env.MONGODB_SESSION_SECRET
                },
                ttl: 60 * 60
            }
        ),
        cookie:
        {
            maxAge: 1000 * 60 * 60
        },
            resave: false,
            saveUninitialized: false
        }
));

/* Creates a basic HTML page so routes can send full HTML responses. */
function page(title, body)
{
    return `
        <!DOCTYPE html>
        <html>
            <head>
                <title>${ title }</title>
            </head>
            <body>
                ${ body }
            </body>
        </html>
    `;
};

/* Creates a reusable error page with a message and return link. */
function errorPage(message, link, linkText)
{
    return page(
        "Error",
        `
            <p>${ message }</p>
            <p><a href="${ link }">${ linkText }</a></p>
        `
    );
};

/* Displays the home page. */
app.get(
    "/",
    function (req, res)
    {
        if (req.session.authenticated)
        {
            res.send(
                page(
                    "Home",
                    `
                        <h1>Hello, ${req.session.name}.</h1>
                        <p>
                            <a href="/members">
                                Go to Members Area
                            </a>
                        </p>
                        <p>
                            <a href="/logout">
                                Logout
                            </a>
                        </p>
                    `
                )
            );

            return;
        };

        res.send(
            page(
                "Home",
                `
                    <h1>Welcome</h1>
                    <p>
                        <a href="/signup">
                            Sign up
                        </a>
                    </p>
                    <p>
                        <a href="/login">
                            Log in
                        </a>
                    </p>
                `
            )
        );
    }
);

/* Displays the signup form. */
app.get(
    "/signup",
    function (req, res)
    {
        res.send(
            page(
                "Sign up",
                `
                    <h1>Create user</h1>

                    <form method="POST" action="/signup">
                        <input
                            name="name"
                            placeholder="name"
                        >
                        <br>

                        <input
                            name="email"
                            placeholder="email"
                        >
                        <br>

                        <input
                            name="password"
                            type="password"
                            placeholder="password"
                        >
                        <br>

                        <button type="submit">
                            Submit
                        </button>
                    </form>
                `
            )
        );
    }
);


/* POST request for the signup page. Validates input. */
app.post(
    "/signup",
    async function (req, res)
    {
        const schema = Joi.object(
            {
                name: Joi.string()
                        .trim()
                        .max(50)
                        .required(),

                email: Joi.string()
                        .trim()
                        .email()
                        .max(100)
                        .required(),

                password: Joi.string()
                        .max(100)
                        .required()
            }
        );

        const validationResult = schema.validate(req.body);

        if (validationResult.error)
        {
            res.send(
                errorPage(
                    "Please provide a valid name, email, and password.",
                    "/signup",
                    "Try again"
                )
            );

            return;
        }

        const name = validationResult.value.name;
        const email = validationResult.value.email.toLowerCase();
        const password = validationResult.value.password;

        const existingUser = await userCollection.findOne(
            {
                email: email
            }
        );

        if (existingUser) {
            res.send(
                errorPage(
                    "An account with this email already exists.",
                    "/signup",
                    "Try again"
                )
            );

            return;
        };

        const hashedPassword = await bcrypt.hash(password, 12);

        await userCollection.insertOne(
            {
                name: name,
                email: email,
                password: hashedPassword
            }
        );

        req.session.authenticated = true;
        req.session.name = name;
        req.session.email = email;

        res.redirect("/members");
    }
);

/* Get request for the login page. */
app.get(
    "/login",
    function (req, res)
    {
        res.send(
            page(
                "Login",
                `
                    <h1>Login</h1>

                    <form method="POST" action="/login">
                        <input
                            name="email"
                            placeholder="email"
                        >
                        <br>

                        <input
                            name="password"
                            type="password"
                            placeholder="password"
                        >
                        <br>

                        <button type="submit">
                            Submit
                        </button>
                    </form>
                `
            )
        );
    }
);

/* POST request for the login page. Validates input. */
app.post(
    "/login",
    async function (req, res)
    {
        const schema = Joi.object(
            {
                email: Joi.string()
                        .trim()
                        .email()
                        .max(100)
                        .required(),

                password: Joi.string()
                            .max(100)
                            .required()
            }
        );

        const validationResult = schema.validate(req.body);

        if (validationResult.error)
        {
            res.send(
                errorPage(
                    "Incorrect email or password format.",
                    "/login",
                    "Try again"
                )
            );

            return;
        };

        const email = validationResult.value.email.toLowerCase();
        const password = validationResult.value.password;

        const user = await userCollection.findOne(
            {
                email: email
            }
        );

        if (!user)
        {
            res.send(
                errorPage(
                    "Invalid email/password combination.",
                    "/login",
                    "Try again"
                )
            );
        
            return;
        };

        const passwordMatches = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatches)
        {
            res.send(
                errorPage(
                    "Invalid password.",
                    "/login",
                    "Try again"
                )
            );

            return;
        };

        req.session.authenticated = true;
        req.session.name = user.name;
        req.session.email = user.email;

        res.redirect("/members");
    }
);

/* Get request for members page. */
app.get(
    "/members",
    function (req, res)
    {
        if (!req.session.authenticated)
        {
            res.redirect("/");
            return;
        };

        const images = [
            "/images/image1.jpg",
            "/images/image2.jpg",
            "/images/image3.jpg"
        ];

        const randomIndex = Math.floor(
            Math.random() * images.length
        );

        const randomImage = images[randomIndex];

        res.send(
            page(
                "Members",
                `
                    <h1>Hello, ${req.session.name}.</h1>

                    <img
                        src="${randomImage}"
                        alt="Random member image"
                        width="300"
                    >

                    <p>
                        <a href="/logout">
                            Sign out
                        </a>
                    </p>
                `
            )
        );
    }
);

/* Discards the session and returns the user to the home page. */
app.get(
    "/logout",
    function (req, res)
    {
        req.session.destroy(
            function ()
            {
                res.clearCookie("connect.sid");
                res.redirect("/");
            }
        );
    }
);

/* Catch all routes that were not defined above. */
app.use(
    function (req, res)
    {
        res.status(404).send(
            page(
                "404",
                `
                    <h1>404</h1>
                    <p>Page not found.</p>
                    <p>
                        <a href="/">
                            Go home
                        </a>
                    </p>
                `
            )
        );
    }
);

/* Starts the server after MongoDB successfully connects. */
connectToDatabase()
    .then(
        function () {
            app.listen(
                port,
                function ()
                {
                    console.log(
                        `Server running on port ${port}`
                    );
                }
            );
        }
    )
    .catch(
        function (error)
        {
            console.error(error);
        }
    );