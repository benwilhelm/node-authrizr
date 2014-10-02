var config = require('../config')
  , passport = require('passport')
  , BasicStrategy = require('passport-http').BasicStrategy
  , LocalStrategy = require('passport-local').Strategy
  , User = require('../models/User').Model
  , url = require('url')
  ;

passport.serializeUser(function(user, done) {
  done(null,user._id);
});

passport.deserializeUser(function(id, done){
  User.findById(id,function(err,user){
    done(err,user) ;
  }) ;
});


  
passport.use(new BasicStrategy(
  function(username, password, done){
    User.getAuthenticated(username, password, done);
  }
)) ;

passport.use(new LocalStrategy(
  { usernameField: config.usernameField },
  function(username,password,done){
    User.getAuthenticated(username, password, function(err,user){
      if (user) {
        return done(err, user) ;
      } else {
        return done(err, user, {message: 'The email or password that you provided was incorrect'});
      }
    }) ;
  }
));

var exports = {
  passport: passport,
  authenticateHmacOrLocal: function(req, res, next){
    if (req.headers.authorization) {
      exports.hmac.authenticate(req, res, next);
    } else {
      exports.local.ensureAuthenticated(req, res, next);
    }
  },
  
  // Basic Strategy
  basic: {
    authenticate: passport.authenticate('basic', {session:false})
  },
  
  // Local Strategy
  local: {
    authenticate: passport.authenticate('local', {
      failureRedirect:config.loginUrl
    }),
    
    ensureAuthenticated: function(req, res, next){
      if (req.isAuthenticated()) { return next(); }
      res.redirect(config.loginUrl) ;
      return false;
    }
  },
  
  // Hmac Strategy (does not use passport)
  hmac: {
    authenticate: function(req,res,next) {
      var header=req.headers.authorization || ''       // get the header
      , token=header.split(/\s+/).pop() || ''          // and the encoded auth token
      , auth=new Buffer(token, 'base64').toString()    // convert from base64
      , parts=auth.split(/:/)                          // split on colon
      , apiKey=parts[0]
      , hash=parts[1]
      ;
      
      var data = {};
      if (req.method === 'GET') {
        var theUrl = url.parse(req.originalUrl, true);
        data = theUrl.query;
      } else {
        data = req.body;
      }
      
      User.verifyHmac(apiKey, hash, data, function(err, user, reason){
        if (user) {
          req.user = user ;
          next() ;
        } else {
          res.status(401) ;
          res.write("Unauthorized") ;
          res.send() ;
        }
      });
    }
  }
};

module.exports = exports;