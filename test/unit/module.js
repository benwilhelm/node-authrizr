
describe("Unit - Authrizr Module Methods", function(){
  
  var suite = this;
  
  before(function(done){
    suite.authrizr = require("../../index");
    done();
  });

  describe("Get method", function(){
    it("should return value for key", function(done){
      var loginUrl = suite.authrizr.get('loginUrl');
      loginUrl.should.eql('/login');
      done();
    });
  });
  
  describe("Set method", function(){
    it("should set value for key", function(done){
      suite.authrizr.set('loginUrl','/sign_in');
      suite.authrizr.get('loginUrl').should.eql('/sign_in');
      done();
    });
  });
});
