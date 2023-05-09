require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Mongostore = require('connect-mongo');
const bcrypt = require('bcrypt');

const saltRounds = 12;

const Joi = require('joi');

const app = express();

const port = process.env.PORT || 3000;

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = require('./databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs')

app.use(express.urlencoded({extended: false}));

var mongoStore = Mongostore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}?retryWrites=true&w=majority`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveOnInitialized: false,
    resave: true,
}
));

function isValidSession(req) {
    if(req.session.authenticated) {
        return true;
    }
    return false;
}

function isAdmin(req) {
    if(req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if(!isValidSession(req)) {
        res.redirect('/login');
        return;
    }
    if(!isAdmin(req)) {
        res.render("errorMessage", {error: "Not authorized to view this page"});
        return;
    }
    next();
}

app.get('/', (req, res) => {
    res.render('index', { username: req.session.username });
});



app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/createUser', (req,res) => {
    res.render('createUser');
});


app.get('/login', (req,res) => {
    res.render('login');
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/signup?error=invalid');
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({username: username, email: email, password: hashedPassword});
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
      res.redirect('/');
      return;
    }
    res.render('members', { username: req.session.username});
  });


app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const validationResult = Joi.string().email().required().validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        var html = `
            <h1>Validation Error</h1>
            <p>${validationResult.error.details[0].message}</p>
            <a href="/login">Try again</a>
        `;
        res.send(html);
        return;
    }

    const user = await userCollection.findOne({ email: email });

    if (!user) {
		var html = `
		<h1>Invalid Login</h1>
		<p>User not found</p>
		<a href="/login">Try again</a>
	`;
	res.send(html);
        return;
    }

    if (await bcrypt.compare(password, user.password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = user.username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        console.log("incorrect password");
        var html = `
            <h1>Invalid Login</h1>
            <p>Incorrect password</p>
            <a href="/login">Try again</a>
        `;
        res.send(html);
        return;
    }
});


app.use('/loggedin', adminAuthorization);
app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    `;
    res.send(html);
});

app.get('/admin', adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({username: 1, email: 1, user_type: 1, _id: 1}).toArray();
    res.render('admin', { users: result });
  });
  
app.post('/admin/promote', async (req, res) => {
    const email = req.body.email;

    try {
      await userCollection.updateOne({ email: email }, { $set: { user_type: 'admin' } });
      console.log('User promoted to admin:', email);
      res.redirect('/admin');
    } catch (error) {
      console.error('Error promoting user:', error);
      res.redirect('/admin');
    }
  });
  
  app.post('/admin/demote', async (req, res) => {
    const email = req.body.email;
    
    try {
      await userCollection.updateOne({ email: email }, { $set: { user_type: 'user' } });
      console.log('Admin demoted to user:', email);
      res.redirect('/admin');
    } catch (error) {
      console.error('Error demoting admin:', error);
      res.redirect('/admin');
    }
  });
  

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        mongoStore.destroy(req.sessionID, (err) => {
            if (err) {
                console.log(err);
            }
            res.redirect('/');
        });
    });
});

app.use(express.static(__dirname + "/public"));
app.use(express.static(__dirname + "/views"));


app.get("*", (req,res) => {
    res.status(404);
    res.render('404');
  })

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 