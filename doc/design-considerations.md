Protocol requirements
=====================

Use Case
--------

An external user visits a (secret) link with his standard browser. By visiting
the link, the browser (User Agent) gains a grant to access protected resources.

The user visits https://staging.example.org/ , and gets the page content without
any user-interaction. The page includes protected resources from
https://images-staging.example.org/.


Requirements
------------

 * Authorization for a particular domain can happen via redirects without
   JavaScript. JavaScript does not work for `<img src="https://images-staging.example.org"/>`
 
 * Authorization should be passed via `Cookie:`-headers. Browsers can't include
   `Authorization: Bearer xxx`-headers in img-requets.


Consequences
------------

 * OAuth2 implicit flow can't be used: The token is put in the Fragment identifier,
   which requires JavaScript to extract it.

 * UMA can't be used (Authorization header)
