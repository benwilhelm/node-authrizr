process.env.NODE_ENV = 'test' ;
var app = require('../server')
  , assert = require('assert')
  , async = require('async')
  , authrizr = require('../../index')
  , crypto = require('crypto')
  , fixtures = require('pow-mongoose-fixtures')
  , helpers = require('../test-helpers')
  , mongoose = require('mongoose')
  , passport = require('passport')
  , passportStub = require('passport-stub')
  , request = require('supertest')
  , should = require('should')
  , store = require('../../lib/db')
  ,   db = store.database
  , User = require('../../models/User').Model
  , testData = {
      foo: 'bar',
      bif: 'baz'
    }
  ;

passportStub.install(app);

describe("Unit - Auth Strategies", function(){

  var suite = this;

  before(function(done){
    async.series([
      function(cb) { helpers.emptyCollections(cb); },
      function(cb) { fixtures.load(__dirname + '/../fixtures/users.js', db, cb); },
      function(cb) {
        User.findOne({email:'user1@example.com'}, function(err, u){
          suite.user1 = u;
          passportStub.logout();
          cb();
        });
      }
    ],done);
  }) ;

  describe("Local Strategy", function(){

    it("should log user in with good credentials", function(done){
      
      var loginUrl = authrizr.get('loginUrl');

      request(app)
      .post(loginUrl)
      .send({email:suite.user1.email, password: 'password123'})
      .expect(302)
      .end(function(err, resp){
        if (err) { console.error(err); }
        resp.header.location.should.eql('/local/account');
        done(err);
      });
    });

    it("should redirect to loginUrl with bad email", function(done){
      
      var loginUrl = authrizr.get('loginUrl');
      request(app)
      .post(loginUrl)
      .send({email:'bad@email.com', password: 'password123'})
      .expect(302)
      .end(function(err, resp){
        resp.header.location.should.eql(loginUrl);
        done(err);
      });
    });

    it("should redirect to loginUrl with bad password", function(done){
      
      var loginUrl = authrizr.get('loginUrl');
      request(app)
      .post(loginUrl)
      .send({email:suite.user1.email, password: 'badpass'})
      .expect(302)
      .end(function(err, resp){
        resp.header.location.should.eql(loginUrl);
        done(err);
      });
    });

    it("should redirect to login page if not logged in", function(done){
      
      var loginUrl = authrizr.get('loginUrl');
      
      request(app)
      .get('/local/account')
      .expect(302)
      .end(function(err,resp){
        resp.header.location.should.eql(loginUrl);
        done(err);
      });
    });
    
    it("should serve requested page if logged in", function(done){
      passportStub.login(suite.user1);

      request(app)
      .get('/local/account')
      .expect(200)
      .end(done);
    });
    
  });
  
  
  describe("Basic Strategy", function(){
    it("should serve requested page when provided proper credentials", function(done){
      request(app)
      .get('/basic/account')
      .auth('user1@example.com','password123')
      .expect(200)
      .end(done);
    });

    it("should return 401 with bad email", function(done){
      request(app)
      .get('/basic/account')
      .auth('baduser@example.com','password123')
      .expect(401)
      .end(function(err, resp){
        resp.text.should.eql("Unauthorized");
        done();
      });
    });

    it("should return 401 with bad password", function(done){
      request(app)
      .get('/basic/account')
      .auth('user1@example.com','badpassword')
      .expect(401)
      .end(function(err, resp){
        resp.text.should.eql("Unauthorized");
        done();
      });
    });
  });

  
  describe("HMAC Strategy", function(){
    it("should serve POST request with properly hashed data", function(done){
      var data = {
        flim: 'flam',
        date: Math.floor(new Date().getTime() / 1000)
      };
      var hash = helpers.hmacData(data, suite.user1.apiSecret);
      request(app)
      .post("/hmac/account")
      .auth(suite.user1.apiKey, hash)
      .send(data)
      .expect(200)
      .end(done);
    });
    
    it("should return 401 when POSTed with no hash", function(done){
      var data = {
        date: Math.floor(new Date().getTime() / 1000)
      };
      
      request(app)
      .post('/hmac/account')
      .auth(suite.user1.apiKey,'')
      .send(data)
      .expect(401)
      .end(done);
    });
    
    it("should return 401 when POSTed with bad hash", function(done){
      var data = {
        date: Math.floor(new Date().getTime() / 1000)
      };
      hash = helpers.hmacData(data, suite.user1.apiSecret);
      data.flim = 'flam';
      
      request(app)
      .post('/hmac/account')
      .auth(suite.user1.apiKey,hash)
      .send(data)
      .expect(401)
      .end(done);
    });
    
    it("should serve GET request with properly hashed data", function(done){
      var theDate = Math.floor( new Date().getTime() / 1000 );
      var data = {
        flim: 'flam',
        date: theDate + '' // cast to string for GET query param
      };
      var hash = helpers.hmacData(data, suite.user1.apiSecret);
      request(app)
      .get("/hmac/account?flim=flam&date=" + theDate)
      .auth(suite.user1.apiKey, hash)
      .expect(200)
      .end(done);
    });

    it("should return 401 when GETed with no hash", function(done){
        var theDate = Math.floor( new Date().getTime() / 1000 );
        var data = {
          flim: 'flam',
          date: theDate + '' // cast to string for GET query param
        };
        
        request(app)
        .get("/hmac/account?flim=flam&date=" + theDate)
        .auth(suite.user1.apiKey,'')
        .expect(401)
        .end(done);
    });

    it("should return 401 when GETed with bad hash", function(done){
        var theDate = Math.floor( new Date().getTime() / 1000 );
        var data = {
          date: theDate + '' // cast to string for GET query param
        };
        hash = helpers.hmacData(data, suite.user1.apiSecret);
        data.flim = 'flam';
        
        request(app)
        .get("/hmac/account?flim=flam&date=" + theDate)
        .auth(suite.user1.apiKey, hash)
        .expect(401)
        .end(done);
    });
  });
  
  
  describe("HmacOrLocal Middleware", function(){
    it('should fail with bad hash when not logged in', function(done){
        var data = {
          date: Math.floor(new Date().getTime() / 1000)
        };
        hash = helpers.hmacData(data, suite.user1.apiSecret);
        data.flim = 'flam';
        
        request(app)
        .post('/hmacorlocal/account')
        .auth(suite.user1.apiKey,hash)
        .send(data)
        .expect(401)
        .end(done);
    });
    
    it('should fail with no hash when not logged in', function(done){
      var data = {
        date: Math.floor(new Date().getTime() / 1000)
      };
      
      request(app)
      .post('/hmacorlocal/account')
      .auth(suite.user1.apiKey,'')
      .send(data)
      .expect(401)
      .end(done);        
    });
    
    it("should redirect to login page if not logged in", function(done){
      
      var loginUrl = authrizr.get('loginUrl');
      
      /* I think this is a race condition.
       * This test fails unless I explicitly log out at the beginning
       * of the test, presumably because the server is keeping the stub
       * logged in accross tests. It also doesn't work to logout in the
       * before() method */
      passportStub.logout();
      
      request(app)
      .get('/hmacorlocal/account')
      .expect(302)
      .end(function(err,resp){
        resp.header.location.should.eql(loginUrl);
        done(err);
      });
    });
    
    it("should serve requested page if logged in", function(done){
      passportStub.logout();
      passportStub.login(suite.user1);

      request(app)
      .get('/hmacorlocal/account')
      .expect(200)
      .end(done);
    });
    
    it("should authenticate with local strategy", function(done){
      passportStub.logout();
      passportStub.login(suite.user1);
    
      request(app)
      .get('/hmacorlocal/account')
      .expect(200)
      .end(done);
    });
    
    it('should authenticate with hmac strategy', function(done){
      var data = {
        flim: 'flam',
        date: Math.floor(new Date().getTime() / 1000)
      };
      var hash = helpers.hmacData(data, suite.user1.apiSecret);
      request(app)
      .post("/hmac/account")
      .auth(suite.user1.apiKey, hash)
      .send(data)
      .expect(200)
      .end(done);
    });
  });
  
});
