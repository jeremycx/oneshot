var http = require('http')
var util = require('util');
var fs = require('fs');
var oneshot = require('../lib/oneshot');


var userlist = {
    "babs": "secret",
    "test": "test"
};

function getUser(details) {
    if (details.username in userlist) {
        details.password = userlist[details.username];
    }
}

var authenticator = new oneshot( {
    expireTimeout:  3600000,
    realm:          "oneshot",
    loginURI:       "/login.html",
    redirectOnFail: true,
    userLookup:     getUser
});

var index = fs.readFileSync("./index.html");


http.createServer(function(req, res) {
    if (req.url.match(/^\/protected/)) {
        var authDetails = authenticator.getAuthDetails(req);
        if (authDetails) {
            getUser(authDetails);
        }
        authenticator.authenticate(req, res, authDetails);

        res.writeHead(200);
        res.end(util.inspect(req));
    } else {
        res.writeHead(200);
        res.end(index);
    }
}).listen(3000);