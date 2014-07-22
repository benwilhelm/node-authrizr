// User Model based on http://devsmash.com/blog/password-authentication-with-mongoose-and-bcrypt

var store = require('../lib/db') 
  , Schema = store.Schema
  , async = require('async')
  , bcrypt = require('bcrypt')
  , crypto = require('crypto')
  , SALT_WORK_FACTOR = 6
  , MAX_LOGIN_ATTEMPTS = 10
  , LOCK_TIME = 2 * 60 * 60 * 1000 // 2 hours
  ;

var sch = function(){
  var UserSchema = new Schema({
    email: {type: String, index: {unique:true}, required: "Please provide a valid email address"} ,
    name: {
      first: {type: String, required: "Please provide a first name"} ,
      last: {type: String, required: "Please provide a last name"}
    },
    password: {type: String, required: "Please choose a password" },
    role_id: {type: String, required: true },
    apiKey: {type: String, required: true, index: {unique:true}},
    apiSecret: {type: String, required: true, index: {unique:true}},
    loginAttempts: { type: Number, required: true, default: 0 },
    lockUntil: { type: Number }
  }) ;
  
  
  // !VIRTUAL ATTRIBUTES
  // =======================
  
  UserSchema.virtual('username').get(function(){
    return this.email ;
  }) ;
  
  UserSchema.virtual('name.full').get(function(){
    return this.name.first + ' ' + this.name.last ;
  }) ;
  
  // used for ACL callback
  UserSchema.virtual('user_id').get(function(){
    return this._id.toString() ;
  }) ;
  
  // used for ACL callback
  UserSchema.virtual('resource_id').get(function(){
    return 'account' ;
  }) ;
  
  UserSchema.virtual('isLocked').get(function(){
    return !!(this.lockUntil && this.lockUntil > Date.now()) ;
  }) ;
  
  
  
  
  // !MIDDLEWARE
  // =======================
  
  
  UserSchema.pre('validate',function(next){
  
    // assign default user role
    if (!this.role_id)
      this.role_id = 'account_user' ;
  
    next() ;
  }) ;
  
  /** encrypt password on save */
  UserSchema.pre('save', function(next){
    var user = this ;
    
    // only hash the password if it has been modified or is new
    if (!user.isModified('password')) return next() ;
    
    // generate salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt){
      if (err) return next(err) ;
      
      // hash the password along with the new salt
      bcrypt.hash(user.password, salt, function(err, hash){
        if (err) return next(err) ;
        
        // override the cleartext password with the hashed one
        user.password = hash ;
        return next() ;
      }) ;
    }) ;
    
  }) ;
  
  
  /** create api secret */
  UserSchema.pre('validate', function(next){
    var user = this ;
    
    // generate new API Key/Secret if either is empty
    if (!user.apiSecret || !user.apiKey) {
      user.resetApiCredentials(next) ;
    } else {
      next() ;
    }
  });
  
  
  // !MODEL VALIDATIONS
  // =======================
  
  UserSchema.path('email').validate(function(value){
    return /^.+@.+\..+$/.test(value) ;
  }, "This does not appear to be a valid email address") ;
  
  UserSchema.path('password').validate(function(value){
    return value.length >= 8 ;
  }, "Your password must be at least 8 characters long");
  
  UserSchema.path('apiKey').validate(function(value){
    return /^[A-Fa-f0-9]{24}$/.test(value) ;
  }, 'API Secret should be generated as a 24-character string (12 hex values)');
  
  UserSchema.path('apiSecret').validate(function(value){
    return /^[A-Fa-f0-9]{48}$/.test(value) ;
  }, 'API Secret should be generated as a 48-character string (24 hex values)');
  
  
  
  // !OBJECT METHODS
  // =======================
  
  UserSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
      if (err) return cb(err) ;
      cb(null, isMatch) ;
    }) ;
  } ;
  
  UserSchema.methods.compareHmac = function(candidateHash, data) {
    var secret = this.apiSecret ;
    var hmac = crypto.createHmac('sha256', secret) ;
    hmac.setEncoding('hex') ;
    data = typeof data === 'string' ? data : JSON.stringify(data) ;
    hmac.write(data) ;
    hmac.end() ;
    var hash = hmac.read() ;
    
    return hash == candidateHash ;
  };
  
  UserSchema.methods.resetApiCredentials = function(cb) {
    var self = this ;
    
    async.parallel([function(next){
      crypto.randomBytes(12, next) ;
    },function(next){
      crypto.randomBytes(24, next) ;
    }], function(err, rslts){
      var key = rslts[0].toString('hex') ;
      var secret = rslts[1].toString('hex') ;
      self.apiKey = key ;
      self.apiSecret = secret ;
      
      if (cb) {
        cb(err, {apiKey:key,apiSecret:secret}) ;
      }
    }) ;  
  } ;
  
  UserSchema.methods.incLoginAttempts = function(cb) {
  
    if (this.lockUntil && this.lockUntil < Date.now()) {
      return this.update({
        $set: {loginAttempts: 1},
        $unset: {lockUntil: 1}
      }, cb) ;
    }
    
    var updates = { $inc: { loginAttempts: 1 } } ;
    if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
      updates.$set = { lockUntil: Date.now() + LOCK_TIME } ;
    }
    return this.update(updates, cb) ;
  } ;
  
  var reasons = UserSchema.statics.failedLogin = {
    NOT_FOUND: 0,
    PASSWORD_INCORRECT: 1,
    MAX_ATTEMPTS: 2,
    NO_TIMESTAMP: 3,
    TIMESTAMP_OUT_OF_BOUNDS: 4,
    BAD_HASH: 5
  } ;
  
  
  
  // !STATIC METHODS
  // =======================
  
  UserSchema.statics.getAuthenticated = function(username, password, cb) {
  
    this.findOne({"email": username}, function(err, user){
      if (err) return cb(err) ;
      
      if (!user)
        return cb(null,null,reasons.NOT_FOUND) ;
      
      user.comparePassword(password, function(err, isMatch){
        if (err) return cb(err) ;
  
        if (isMatch) {       
  
          if (!user.loginAttempts && !user.lockUntil) return cb(null, user) ;
    
          var updates = {
            $set: { loginAttempts: 0 },
            $unset: { lockUntil: 1 }
          } ;
          
          return user.update(updates, function(err){
            if (err) return cb(err) ;
            return cb(null, user) ;
          }) ;
        }
        
        user.incLoginAttempts(function(err){
          if (err) return cb(err) ;
          return cb(null,null,reasons.PASSWORD_INCORRECT) ;
        });
      }) ;
      
    }) ;
  } ;
  
  UserSchema.statics.verifyHmac = function(apiKey, hashed, payload, cb) {
  
    // check for presence of timestamp
    if (!payload.date) 
      return cb(null, null, reasons.NO_TIMESTAMP) ;
      
  
    // 3 min threshold
    var threshold = 3 * 60 * 1000 ;
    var diff = payload.date - Math.floor(new Date().getTime() / 1000) ;
    if (Math.abs(diff) > threshold) {
      return cb(null, null, reasons.TIMESTAMP_OUT_OF_BOUNDS) ;
    }
  
    // timestamp OK, find user and compare hmac
    this.findOne({apiKey: apiKey}, function(err, user){
      if (!user) 
        return cb(null,null,reasons.NOT_FOUND) ;
      
      if(user.compareHmac(hashed, payload)) {
        return cb(null, user) ;
      } else {
        return cb(null, null, reasons.BAD_HASH);
      }
    });
  };
  
  return UserSchema;
};

module.exports = {
  Model: store.mongoose.model('User', sch()),
  Schema: sch
};
