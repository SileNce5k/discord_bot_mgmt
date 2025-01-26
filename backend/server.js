const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;
const path = require('path')
const cookieParser = require('cookie-parser')
const argon2 = require('argon2')
const crypto = require('crypto')

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(cookieParser())

app.use((req, res, next) => {
    console.log(`${req.ip} ${req.method} ${req.url}`)
    next()
})


app.use((req, res, next) => {

    const authenticatedUser = verifyAuthToken(req.cookies.auth_token);
    
    if(authenticatedUser){
        res.locals.user = getUser(authenticatedUser.user_id)
    }
    next()
})

const frontendPath = {
    views: path.join(__dirname, "..", "frontend", "views"),
    public:  path.join(__dirname, "..", "frontend", "public")
}

function _frontendPath(isPublic, file){ 
    if(isPublic)
        return path.join(frontendPath.public, file)
    return path.join(frontendPath.views, file)
    
}

app.use(express.static(frontendPath.public));
app.set('views', frontendPath.views);


const databasePath = "data/database.db";
const db = require('better-sqlite3')(databasePath);


db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        hashed_password TEXT,
        email TEXT,
        created_at INTEGER,
        is_verified INTEGER,
        is_administrator INTEGER
        )`
).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS tokens (
        token PRIMARY KEY UNIQUE,
        user_id INTEGER,
        expires_at INTEGER
        )`
).run();


function verifyAuthToken(authToken){
    let authenticatedUser;
    try {
        authenticatedUser = db.prepare("SELECT * FROM tokens WHERE token = ?").get(authToken);
    } catch (error) {
        console.error(error)
        return false;
    }
    if(!authenticatedUser) return false;
    if(authenticatedUser.token !== authToken) return false;
    if(authenticatedUser.expires_at <= new Date().valueOf()) return false;
    return authenticatedUser; 
}

function getUser(userid){
    let user;
    try {
        user = db.prepare("SELECT user_id, username, email, created_at, is_verified FROM users WHERE user_id = ?").get(userid)
        
    } catch (error) {
        console.error(error);
        return false;
    }
    return user;
}

app.get('/users/:id/settings', (req, res) => {
    let userId = Number(req.params.id);
    if(res.locals.user){
        if(res.locals.user.user_id === userId){
            res.render("user_settings", {id: userId})
        }else {
            res.redirect(`/users/${res.locals.user.user_id}/settings`)
        }
    }else {
        res.redirect("/")
    }
})

app.get('/register', (req, res) => {
    if(res.locals.user){
        res.redirect("/");
        return;
    }
    
    res.render("register")
})

app.get('/', (req, res) => {
    if(res.locals.user){
        const footer = "";
        res.render("dashboard", {user: res.locals.user, footer: footer})
    }else{
        res.render("invalid_login")
    }
})

app.get('/logout', (req, res) => {

    res.clearCookie("auth_token").redirect("/")
})

app.get('/login', (req, res) => {
    if(req.query.invalid === "yes"){
        let invalidMessage = "Username or password incorrect"
        res.render("login", {invalid_login: true, invalid_message: invalidMessage})
    }else{
        res.render("login", {invalid_login: false, invalid_message: ""})
    }
})

app.post('/api/v1/login', async (req, res,) => {
    const username = req.body.username;
    const password = req.body.password;
    let user;
    try {
        user = db.prepare("SELECT user_id, hashed_password FROM users WHERE username = ?").get(username);
    } catch (error) {
        console.error(error) 
    }
    if(!user){
        res.redirect("/login?invalid=yes")
    }else {
        let isVerified = false;
        try {
            isVerified = await argon2.verify(user.hashed_password, password)
        } catch (error) {
            console.error(error)
            res.status(500).send("Internal Server Error")
        }
        if(isVerified){
            const maxAge = 2592000000 // 30 days in milliseconds.
            const maxAgeTimestamp = new Date().valueOf() + maxAge
            const token = crypto.randomBytes(128).toString('base64')
            try { // TODO: Improve this logic...
                db.prepare("INSERT INTO tokens ( token, user_id, expires_at ) VALUES (?, ?, ?)").run(token, user.user_id, maxAgeTimestamp)
                res.cookie("auth_token", token, {maxAge: maxAge, secure: true, httpOnly: true, sameSite: 'lax'}).redirect("/")
            } catch (error) {
                console.log(error)
                res.redirect("/")
            }
        }else{
            res.redirect("/login?invalid=yes")
        }
    }

})


function verifyRegistration(username, password, email){
    let validationResult = {
        isValid: false,
        username: false,
        password: false,
        email: false
    }
    
    if(username.length >= 3) validationResult.username = true;
    if(password.length >= 8) validationResult.password = true;
    if(email) validationResult.email = true;

    if(validationResult.username && validationResult.password && validationResult.email) validationResult.isValid = true;
    return validationResult
}


app.post('/api/v1/register', async (req, res) => {
    let username = req.body.username;
    const password = req.body.password;
    const email = req.body.email;
    if(!username || !password || !email){
        res.render("register_missing")
    }else if(verifyRegistration(username, password, email).isValid){
        const hashed_password = await argon2.hash(password);
        const createdAt = new Date().getTime();
        const isVerified = 0;
        try {
            db.prepare("INSERT INTO users (username, hashed_password, email, created_at, is_verified) VALUES (?, ?, ?, ?, ?)").run(username, hashed_password, email, createdAt, isVerified)
        } catch (error) {
            console.error(error)
            // redirect to /register with some stuff
        }
        res.redirect("/login");
    }else {
        res.render("register_missing") // TODO: Create a separate page for this.
    }
})




app.listen(port, () => {
    console.log(`INFO:\tServer started at http://127.0.0.1:${port}`);
})



process.on('SIGINT', () => {
    console.log("Exiting safely...")
    db.close();
    process.exit();
});