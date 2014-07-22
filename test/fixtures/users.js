if (process.env.NODE_ENV != 'endtoend')
  process.env.NODE_ENV = 'test' ;

var projRoot = '../../' ;
var ObjectId = require('mongodb').BSONNative.ObjectID
    ;

module.exports.User = [
  
  { // user one
    _id: new ObjectId(),
    email:'user1@example.com',
    name: {
      first: 'User',
      last: 'One',
    },
    password:'password123'
  }
  
];