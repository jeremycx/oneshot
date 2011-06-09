Introduction
============
This module implements HTTP digest authentication in such a way that
browsers can authenticate with a custom login form, and still get all
the advantages of HTTP digest authentication.

The major change to "standard" digest authentication is the tweaking
of return codes from the digest module. In this implementation, the
module will only return a 401 repsonse if there is a problem with the
nonce. All other authentication problems (bad password, etc) will
return a 400 so the ajax login form can handle the error.

For the purposes of this module, no nonce (ie no authentication header
at all), is considered a "bad nonce".

So, therefore, if we try to POST via AJAX to a URI protected by this
module, the first attempt will reply with a 401 (as there is no
authentication header in the request, and thus no nonce). The AJAX
libraries will silently re-send the request with the credentials
provided in the AJAX invocation.

Now, if the module determines the digest is incorrect (bad username or
password), then it will return a 400, and this error can be trapped by
the login form. No login popup appears.

If a user tries to proceed directly to a page protected by the login
form, the module will either pop up a browser-default login box, or it
can be configured to redirect the user to the default login page.

So, FINALLY we have free and well-understood authentication scheme.

Lastly, since this is a challenge-based authenitcation scheme, you may
think you have to store plaintext passwords to make it work. Not so!
You can pre-calculate the A1 hash and store that. The module works
just fine with a pre-baked A1.

