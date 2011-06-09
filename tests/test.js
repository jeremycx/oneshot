var http = require('http')
var util = require('util');
var fs = require('fs');
var oneshot = require('../lib/oneshot');


var userlist = {
    "babs": "38f64f6d049faaf3499e6e453fdfe92b",
    "test": "2ce3e11ca6b806b4c8c455d348e8dc6e"
};

function getUser(details) {
    if (details.username in userlist) {
        details.a1 = userlist[details.username];
    }
}

var authenticator = new oneshot( {
    expireTimeout:  3600000,
    realm:          "oneshot",
    loginURI:       "/login.html",
    landingURI:     "/protected/index.html",
    redirectOnFail: true,
    userLookup:     getUser
});

var index = fs.readFileSync("./index.html");
var logoutpage = fs.readFileSync("./logout.html");


http.createServer(function(req, res) {
    if (req.url.match(/^\/protected/)) {
        var authDetails = authenticator.getAuthDetails(req);
        if (authDetails) {
            getUser(authDetails);
        }
        authenticator.authenticate(req, res, authDetails);

        res.writeHead(200);
        res.end(logoutpage);
    } else {
        res.writeHead(200);
        res.end(index);
    }
}).listen(3000);