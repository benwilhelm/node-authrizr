var appRoot = ".."
  , async = require('async')
  , crypto = require('crypto')
  , fixtures = require('pow-mongoose-fixtures')
  , store = require('../lib/db')
  ,   db = store.database
  , User = require('../models/User')
  ;

module.exports = {

  emptyCollections: function(done){
    async.parallel([
      function(callback){
        var collection = store.mongoose.connection.collections.users;
        if (collection) {
          collection.remove(callback) ;
        } else {
          callback();
        }
      }
    ],done);
  },
  
  loadFixtures: function(done) {
    module.exports.emptyCollections(function(err,rslt){
      async.parallel([
        function(callback){
          fixtures.load(appDir + '/users.js',db,callback);
        },
      ],done);
    });
  },
  
  hmacData: function(data, secret) {
    var hmac = crypto.createHmac('sha256',secret) ;
    hmac.setEncoding('hex') ;
    hmac.write(JSON.stringify(data)) ;
    hmac.end() ;
    return hmac.read() ;
  }
};