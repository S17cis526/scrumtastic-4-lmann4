module.exports = {
  create: create,
  update: update,
  read: read
}

var json = require('./../lib/form-json');
var encryption = require('./../lib/encryption');

function create(req, res, db) {
  json(req, res, function(req, res) {
    var user = req.body;
    var salt = encryption.salt();
    var cryptedPassword = encryption.digest(user.password + salt);
    db.run('INSERT INTO users (eid, email, firstName, lastName, cryptedPassword, salt) VALUES(?, ?, ?, ?, ?, ?);', [
      user.eid,
      user.email,
      user.firstName,
      user.lastName,
      cryptedPassword,
      salt
    ], function(err))
  })
}

function read(req, res, db) {
  var id = req.params.id;
  db.get('SELECT eid, email, firstName, lastName FROM user WHERE id=?', [id], function(user) {
    res.setHeader("Content-Type", "text/json");
    res.end(JSON.stringify(user))
  })
}
