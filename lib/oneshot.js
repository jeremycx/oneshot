var crypto = require('crypto');
var url = require('url');

module.exports = digestAuth;

function digestAuth(params) {
    var self = this;

    params.expireTimeout = params.expireTimeout ? params.expireTimeout : 3600000;
    params.realm = params.realm ? params.realm : "oneshot";
    params.opaque = params.opaque ? params.opaque : "oneshot";
    params.logoutstring = params.logoutstring ? params.logoutstring : "logout";

    if (!("landingURI" in params)) {
        throw new Error("You must provide a landing URI");
    }
    if (!("loginURI" in params)) {
        throw new Error("You must provide a login URI");
    }

    var nonces = {};

    self.isLoginURI = function(req) {
        if (req.headers.referer) {
            var parts = url.parse(req.headers.referer);
            if (parts.pathname == params.loginURI) {
                return true;
            }
        }
        return false;
    }

    self.checkLogout = function(req) {
        var re = new RegExp("\\?" + params.logoutstring);
        return req.url.match(re);
    }

    self._sendLogout = function(req, res) {
//        console.log("Sending bogus Auth header");
//        var header = "Bogus/"
//	res.writeHead(401, {"WWW-Authenticate": header});
//        res.end('<html><head><meta http-equiv="refresh" content="0;url=http://jc-dev:3000/login.html"></head></html>');
        res.writeHead(200);
        res.end('<html><head><meta http-equiv="refresh" content="0;url=http://jc-dev:3000/login.html"></head></html>');
        return true;
    }

    self._sendRedirect = function(req, res) {
        console.log("Send redirect "+req.url);
        res.writeHead(307, { "Location": params.loginURI });
        res.end("");
        return true;
    }

    self._sendChallenge = function(req, res, nonce) {
        console.log("Send challenge "+req.url);
        var header = "Digest realm=\""+params.realm+"\", qop=\"auth\", nonce=\""+nonce+"\", opaque=\""+params.opaque+"\"";
	res.writeHead(401, {"WWW-Authenticate": header});
	res.end("<!DOCTYPE html>\n<html><head><title>401 Unauthorized</title>"+
                "</head><body><h1>401 Unauthorized</h1>"+
                "<p>This page requires authorization.</p></body></html>");
    }

    self._sendForbidden = function(req, res, reason) {
        console.log("Send Forbidden "+req.url);
        res.writeHead(403, { "x-reason": reason } );
        res.end("<!DOCTYPE html>\n<html><head><title>403 Forbidden</title>"+
                "</head><body><h1>403 Forbidden</h1>"+
                "<p>This page requires authorization.</p></body></html>");
    }

    self.md5 = function(str) {
        var hash = crypto.createHash("MD5");
        hash.update(str);
        return hash.digest("hex");
    }

    self.getAuthDetails = function(req) {
        if (!("authorization" in req.headers)) {
            return;
        }
        var header = req.headers.authorization;

        var authtype = header.match(/^(\w+)\s+/);
        if (authtype === null) {
	    return false;
        }
        if (authtype[1].toLowerCase() != "digest") {
	    // We currently don't support any other auth methods.
	    return false;
        }
        header = header.slice(authtype[1].length);

        var dict = {};
        var first = true;
        while (header.length > 0) {
	    // eat whitespace and comma
	    if (first) {
	        first = false;
	    } else {
	        if (header[0] != ",") {
		    return false;
	        }
	        header = header.slice(1);
	    }
	    header = header.trimLeft();

	    // parse key
	    var key = header.match(/^\w+/);
	    if (key === null) {
	        return false;
	    }
	    key = key[0];
	    header = header.slice(key.length);

	    // parse equals
	    var eq = header.match(/^\s*=\s*/);
	    if (eq === null) {
	        return false;
	    }
	    header = header.slice(eq[0].length);

	    // parse value
	    var value;
	    if (header[0] == "\"") {
	        // quoted string
	        value = header.match(/^"([^"\\\r\n]*(?:\\.[^"\\\r\n]*)*)"/);
	        if (value === null) {
		    return false;
	        }
	        header = header.slice(value[0].length);
	        value = value[1];
	    } else {
	        // unquoted string
	        value = header.match(/^[^\s,]+/);
	        if (value === null) {
		    return false;
	        }
	        header = header.slice(value[0].length);
	        value = value[0];
	    }
	    dict[key] = value;

	    // eat whitespace
	    header = header.trimLeft();
        }

        return dict;
    }

    self.genA1 = function(username, password) {
        return self.md5(username+":"+params.realm+":"+password);
    }

    self.expireNonce = function(nonce) {
        delete nonces[nonce];
    }

    self.createNonce = function() {
        var nonce = self.md5(new Date().getTime()+"privstring");
        nonces[nonce] = {
	    count: 0,
	};
	setTimeout(self.expireNonce,params.expireTimeout, nonce);
        return nonce;
    }

    self.doAuthenticate = function(req, res, authDetails) {
        if (!authDetails) {
            // first request - send a challenge
            self.sendChallenge(req, res, self.createNonce());
            return false;
        }

        if (!(authDetails.nonce in nonces)) {
            self.sendChallenge(req, res, self.createNonce());
            console.log("Nonce invalid");
	    return false;
        }

        if (authDetails.algorithm == "MD5-sess") {
            self.sendForbidden(req, res, "Unsupported algorithm");
            return false;
        }

        // either calculate a1, or pull a pre-baked a1 from authDetails
        var a1;
        if ("a1" in authDetails) {
            a1 = authDetails.a1;
        } else {
            a1 = self.genA1(authDetails.username, authDetails.password);
        }

        // calculate a2
            var a2;
        if (authDetails.qop == "auth-int") {
	    // TODO: implement auth-int
            self.sendForbidden(req, res, "unsupported auth-int");
	    return false;
        } else {
	    a2 = req.method+":"+authDetails.uri;
        }

        // calculate request digest
        var digest;
        if (!("qop" in authDetails)) {
	    // For RFC 2069 compatibility
	    digest = self.md5(a1+":"+authDetails.nonce+":"+self.md5(a2));
        } else {
	    if (authDetails.nc <= nonces[authDetails.nonce].count) {
                self.sendChallenge(req, res, self.createNonce());
	        return false;
	    }
	    nonces[authDetails.nonce].count = authDetails.nc;
	    digest = self.md5(a1+":"+authDetails.nonce+":"+authDetails.nc+
                         ":"+authDetails.cnonce+":"+authDetails.qop+":"+self.md5(a2));
        }

        if (digest == authDetails.response) {
	    return authDetails.username;
        } else {
            self.sendForbidden(req, res, "response mismatch");

	    return false;
        }
    }

    self.authenticate = function(req, res, authDetails) {
        console.log("New auth: "+req.headers.authorization);
        console.log(authDetails);

        // See if the request is from the loginURI
        if (self.isLoginURI(req)) {
            console.log("Is login URI");
            self.sendForbidden = self._sendForbidden;
            self.sendChallenge = self._sendChallenge;
            self.sendRedirect = self._sendForbidden;
            self.sendLogout = self._sendForbidden;
        } else {
            // we drop back to default behaviour
            if (params.redirectOnFail) {
                self.sendForbidden = self._sendRedirect;
                self.sendChallenge = self._sendRedirect;
            } else {
                self.sendForbidden = self._sendChallenge;
                self.sendChallenge = self._sendChallenge;

            }
            self.sendRedirect = self._sendRedirect;
            self.sendLogout = self._sendLogout;
        }

        if (self.checkLogout(req)) {
            // remove the nonce from memory. Therefore, the next request
            // will be replied to with a challenge.
            console.log("Logout requested");
            if (authDetails) {
                self.expireNonce(authDetails.nonce);
            }
            self.sendLogout(req, res);
            return false;
        }

        var username = self.doAuthenticate(req, res, authDetails);

        if (username) {
            req.remoteUser = username;
            return username;
        }
        return false;
    }
    
    return self;
}

