var mongoose = require('mongoose'); 
var dbName = 'authrizr_testing' ;
mongoose.connect('mongodb://localhost/authrizr_testing') ;

module.exports = {
  mongoose: mongoose,
  Schema: mongoose.Schema,
  database: mongoose.connection
};
