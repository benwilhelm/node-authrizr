var express = require('express')
  , app = module.exports = express()
  , authrizr = require('../index')
  , bodyParser = require('body-parser')
  , methodOverride = require('method-override')
  , passport = require('passport')
  ;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));
app.use(methodOverride());
app.use(passport.initialize());
app.use(passport.session({
  secret: 'foo',
  saveUninitialized: true,
  resave: true
}));

app.use("/local/*", authrizr.authStrategies.local.ensureAuthenticated);
app.use("/basic/*", authrizr.authStrategies.basic.authenticate);
app.use("/hmac/*",  authrizr.authStrategies.hmac.authenticate);

app.route('/')
.get(function(req, res, next){
  res.send('ok');
});


app.route('/login')
.get(function(req, res, next){
  res.send('ok');
})
.post(authrizr.authStrategies.local.authenticate, function(req, res, next){
  res.redirect('/local/account');
});


app.route('/local/account')
.get(function(req, res, next){
  res.send('ok');
});

app.route('/basic/account')
.get(function(req, res, next){
  res.send('ok');
});

app.route('/hmac/account')
.all(function(req, res, next){
  res.send('ok');
});

