1. create spotify dev account
2. note down Client ID for later
3. set redirect rule accordingly (in my case i deployed this static website so the Redirect URI is the exact https://websitename.tld, if selfhosted or in lan or so http://127.0.0.1/callback
4. generate hash (optional) -> look into app.js how to generate with powershell easily and save it
5. deploy webserver how you want to
6. login with client id and the pw
7. have fun
