var appRoot = ".."
  , async = require('async')
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
  
};