var U = require('./models/User')
  , authStrategies = require('./middleware/auth-strategies')
  , config = require('config')
  ;

module.exports = {
  User: U,
  authStrategies: authStrategies,
  
  set: function(key, value) {
    config[key] = value;
  },
  
  get: function(key) {
    return config[key];
  }
};
