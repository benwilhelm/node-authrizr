process.env.NODE_ENV = 'test' ;
var assert = require('assert')
  , async = require('async')
  , fixtures = require('pow-mongoose-fixtures')
  , helpers = require('../test-helpers')
  , should = require('should')
  , crypto = require('crypto')
  , store = require('../../lib/db')
  , db = store.database
  , User = require('../../models/User').Model
  , testData = {
      foo: 'bar',
      bif: 'baz'
    }
  ;


function hmacData(data, secret) {
  var hmac = crypto.createHmac('sha256',secret) ;
  hmac.setEncoding('hex') ;
  hmac.write(JSON.stringify(data)) ;
  hmac.end() ;
  return hmac.read() ;
}

function testUser(email) {
  return new User({
    email: email || 'userx@example.com',
    password: 'password123',
    name: {
      first: 'firstName',
      last: 'lastName'
    }
  });
}
  
describe("Unit - User", function(){

  var user1;

  before(function(done){
    async.series([
      function(cb){ helpers.emptyCollections(cb); },
      function(cb){ fixtures.load(__dirname + '/../fixtures/users.js', db, cb); },
      function(cb){
        User.findOne({email:'user1@example.com'}, function(err, u){
          user1 = u;
          cb();
        });
      }
    ],done);
  }) ;
  
  describe("username virtual property", function(){
    it("should alias user's email address", function(done){
      assert.equal('user1@example.com', user1.username, "User's username property should alias the email property");
      done() ;
    });
  }) ;

  describe("resetApiCredentials method", function(){
    it("Should generate new apiKey and apiSecret properties",function(done){
      var user = new User() ;
      user.resetApiCredentials(function(err, creds){
        assert.equal(err,null) ;
        assert.ok( /^[A-Fa-f0-9]{24}$/.test(creds.apiKey) ) ;
        assert.ok( /^[A-Fa-f0-9]{48}$/.test(creds.apiSecret) ) ;
        creds.apiKey.should.eql(user.apiKey) ;
        creds.apiSecret.should.eql(user.apiSecret) ;
        done() ;
      });
    });
  }) ;

  describe("comparePassword method",function(){
    it("should return true if passwords match", function(done){
      user1.comparePassword('password123', function(err, isMatch){
        assert.ok(isMatch) ;
        done() ;
      }) ;      
    });

    it("should return false if passwords don't match",function(done){
      user1.comparePassword('passwordWrong', function(err, isMatch){
        assert.ok(!isMatch) ;
        done() ;
      }) ;
    }) ;

  }) ;
  
  
  describe("isLocked virtual property", function(){
    it("should return true if lockUntil is in the future", function(done){
      user1.lockUntil = Date.now() + 2000 ;
      assert.ok(user1.isLocked) ;
      done() ;
    });
  }) ;
  

  describe("incLoginAttempts method", function(){  
    it("should increment loginAttempts if less than MAX_ATTEMPTS", function(done){
      assert.equal(user1.loginAttempts, 0, 'verify starting loginAttempts 0') ;
      user1.incLoginAttempts(function(){
        User.findById(user1._id, function(err,u){
          assert.equal(u.loginAttempts, 1, 'loginAttempts should be 1') ;
          done() ;
        }) ;
      }) ;
    }) ;

    it("should reset to 1 if lock expired", function(done){
      user1.loginAttempts = 10 ;
      user1.lockUntil = Date.now() - 1000 ;
      user1.save(function(err,u){
        if (err) console.error(err);
        assert.equal(u.loginAttempts, 10, 'verify starting loginAttempts 10') ;
        u.incLoginAttempts(function(){
          User.findById(u._id, function(err,u){
            assert.equal(u.loginAttempts, 1, 'loginAttempts should be 1') ;
            assert.equal(u.lockUntil, null, "lockUntil should be null") ;
            done() ;
          }) ;
        }) ;
      }) ;
    }) ;


    it("should lock account with too many attempts", function(done){
      user1.loginAttempts = 9 ;
      user1.lockUntil = null;
      user1.save(function(err,u){
        if (err) console.error(err);
        assert.equal(u.loginAttempts, 9, 'verify starting loginAttempts 9') ;
        u.incLoginAttempts(function(){
          User.findById(u._id, function(err,u){
            if (err) console.error(err);
            assert.equal(u.loginAttempts, 10, 'loginAttempts should be 10') ;
            var secsMin = 2 * 60 * 60 * 1000 - 100 ;
            var secsMax = 2 * 60 * 60 * 1000 + 100 ;
            var diff = u.lockUntil - Date.now() ;
            var withinRange = diff > secsMin && diff < secsMax ;
            assert.ok(withinRange, "lockUntil should be 2 hours in the future") ;
            done() ;
          }) ;
        }) ;
      }) ;
    }) ;

  });


  describe("getAuthenticated method", function(){  
    it("should return authenticated user on success", function(done){
      User.getAuthenticated(user1.username, 'password123', function(err,user,reason){
        assert.equal(user.email, user1.email) ;
        done() ;
      });
    });


    it("should return null for user and 1 for reason with bad password", function(done){
      User.getAuthenticated(user1.username, 'wrongpassword', function(err,user,reason){
        assert.equal(err,null) ;
        assert.equal(user,null) ;
        assert.deepEqual(reason,1) ;
        User.findById(user1._id,function(err,u){
          assert.equal(u.loginAttempts,1) ;
        });
        done() ;
      });
    }) ;

    it("should return null for user and 0 for reason if user doesn't exist", function(done){
      User.getAuthenticated('wronguser', 'password123', function(err,user,reason){
        assert.equal(err,null) ;
        assert.equal(user,null) ;
        assert.deepEqual(reason,0) ;
        done() ;
      }) ;
    }) ;

  });


  describe("compareHmac method", function(){
    it("should return true on success", function(done){        
      var hash = hmacData(testData, user1.apiSecret);
      assert.ok(user1.compareHmac(hash, testData));
      done() ;
    });
    
    it("should return false with additional parameters", function(done){
      var newData = JSON.parse(JSON.stringify(testData)) ;
      newData.flim = 'flam';
      var hash = hmacData(newData, user1.apiSecret) ;

      user1.compareHmac(hash, testData).should.eql(false) ;
      done() ;
    });
  });


  describe("verifyHmac method", function(done){
    it("should return user on success", function(done){
      testData.date = Math.floor(new Date().getTime() / 1000) ;
      var hash = hmacData(testData, user1.apiSecret) ;
      
      User.verifyHmac(user1.apiKey, hash, testData, function(err, user, reason){
        assert.equal(err, null) ;
        assert.equal(reason, null);
        user.email.should.eql('user1@example.com') ;
        done() ;
      });
    });
    
    it("should fail with no user found (bad api key)", function(done){
      testData.date = Math.floor(new Date().getTime() / 1000) ;
      var hash = hmacData(testData, user1.apiSecret) ;
      
      User.verifyHmac('badapikey', hash, testData, function(err, user, reason){
        assert.equal(err,null) ;
        assert.equal(user,null) ;
        assert.deepEqual(reason,0) ;
        done() ;
      });
    });
    
    it("should fail with no timestamp", function(done){
      var hash = hmacData(testData, user1.apiSecret) ;
      testData.date = null;
      User.verifyHmac(user1.apiKey, hash, testData, function(err, user, reason){
        assert.equal(err,null) ;
        assert.equal(user,null) ;
        assert.deepEqual(reason,3) ;
        done() ;
      });
    });
    
    it("should fail with old timestamp", function(done){
      testData.date = Date.UTC(2013,12,31) ;
      var hash = hmacData(testData, user1.apiSecret) ;
      User.verifyHmac(user1.apiKey, hash, testData, function(err, user, reason){
        assert.equal(err,null) ;
        assert.equal(user,null) ;
        assert.deepEqual(reason,4) ;
        done() ;
      });
    });
  });


  describe("Model Validations", function(){  
    it("should require valid email address", function(done){
      user1.email = 'bwilhelm' ;
      user1.save(function(err, u, numberAffected){
        err.errors.email.message.should.eql("This does not appear to be a valid email address") ;
        err.errors.email.path.should.eql('email') ;
        err.errors.email.value.should.eql("bwilhelm") ;
        done() ;
      }) ;
    });

    it("should hash password on save", function(done){
      var user = testUser('userA@example.com') ;
      user.save(function(err,u){
        if (err) console.error(err) ;
        assert.equal(err,null,'should be no error on save') ;
        assert.equal(u.email,'userA@example.com', "user should be saved with email 'user@example.com'") ;
        assert.notEqual(u.password, 'password123', 'Password should not be in plain text') ;
        done() ;
      });
    }) ;


    it("should generate API key on save", function(done){
      var user = testUser('userB@example.com') ;
      user.save(function(err,u){
        if (err) console.error(err) ;
        assert.equal(err,null,'should be no error on save') ;
        assert.ok(u.apiKey) ;
        assert.ok( /^[\w\d]{24}$/.test(u.apiKey) ) ;
        done() ;
      }) ;
    }) ;

    it("should not regenerate API key on subsequent saves", function(done){
      var user = testUser('userC@example.com') ;
      var testKey ;
      user.save(function(err, u){
        if (err) console.error(err) ;
        testKey = u.apiKey ;
        u.email = 'changed@example.com' ;
        u.save(function(err, u){
          assert.equal(u.email, 'changed@example.com', "Username should be updated") ;
          assert.ok(u.apiKey, 'apiKey should not be null') ;
          assert.ok( /^[\w\d]{24}$/.test(u.apiKey), 'apiKey should be 24 character string' ) ;
          assert.equal(testKey, u.apiKey, "API Key should be unchanged") ;
          done() ;
        }) ;
      });
    });

    it("should generate API secret on save", function(done){
      var user = testUser('userD@example.com') ;
      user.save(function(err,u){
        if (err) console.error(err) ;
        assert.equal(err,null,'should be no error on save') ;
        assert.ok(u.apiSecret) ;
        assert.ok( /^[\w\d]{48}$/.test(u.apiSecret) ) ;
        done() ;
      }) ;
    }) ;


    it("should not regenerate API secret on subsequent saves", function(done){
      var user = testUser('userE@example.com');
      var testSecret ;
      user.save(function(err, u){
        if (err) console.error(err) ;
        testSecret = u.apiSecret ;
        u.email = 'changed2@example.com' ;
        u.save(function(err, u){
          assert.equal(u.email, 'changed2@example.com', "Username should be updated") ;
          assert.ok(u.apiSecret) ;
          assert.ok( /^[\w\d]{48}$/.test(u.apiSecret) ) ;
          assert.equal(testSecret, u.apiSecret, "API Secret should be unchanged") ;
          done() ;
        }) ;
      });
    });

  });
  
}) ;
