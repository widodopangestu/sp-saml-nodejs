var http = require('http');
var fs = require('fs');
var express = require("express");
var dotenv = require('dotenv');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');

dotenv.load();

const CALLBACK_URL=process.env.CALLBACK_URL;
const ENTRY_POINT=process.env.ENTRY_POINT;
const ISSUER=process.env.ISSUER;
const SESSION_SECRET = process.env.SESSION_SECRET;

console.log(`CALLBACK_URL : ${CALLBACK_URL}`);
console.log(`ENTRY_POINT : ${ENTRY_POINT}`);
console.log(`ISSUER : ${ISSUER}`);
console.log(`SESSION_SECRET : ${SESSION_SECRET}`);
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var samlStrategy = new saml.Strategy({
  // URL that goes from the Identity Provider -> Service Provider
  callbackUrl: CALLBACK_URL,
  // URL that goes from the Service Provider -> Identity Provider
  entryPoint:ENTRY_POINT,
  // Usually specified as `/shibboleth` from site root
  issuer: ISSUER,
  identifierFormat: null,
  // Service Provider private key
  decryptionPvk: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
  // Service Provider Certificate
  privateCert: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
  // Identity Provider's public key
  cert: fs.readFileSync(__dirname + '/cert/idp_cert.pem', 'utf8'),
  validateInResponseTo: false,
  disableRequestedAuthnContext: true
}, function(profile, done) {
  return done(null, profile); 
});

passport.use(samlStrategy);

var app = express();
app.set('view engine', 'pug');

app.use(cookieParser());
app.use(bodyParser());
app.use(session({secret: SESSION_SECRET}));
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated())
    return next();
  else
    return res.redirect('/login');
}

app.get('/',
  function(req, res) {
    if (req.isAuthenticated())
      res.render('auth', { title: 'User Login', user: req.user});
    else
      res.render('index', { title: 'Home', message: 'Hello there!'});
  }
);

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function (req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
   passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.get('/login/fail', 
  function(req, res) {
    res.status(401).send('Login failed');
  }
);

app.get('/Shibboleth.sso/Metadata', 
  function(req, res) {
    res.type('application/xml');
    res.status(200).send(samlStrategy.generateServiceProviderMetadata(fs.readFileSync(__dirname + '/cert/cert.pem', 'utf8')));
  }
);

//general error handler
app.use(function(err, req, res, next) {
  console.log("Fatal error: " + JSON.stringify(err));
  next(err);
});
var server = app.listen(4006, function () {
  console.log('Listening on port %d', server.address().port)
});

