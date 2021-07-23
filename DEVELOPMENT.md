## Development

This software is provided *as is* under MIT license.

It may contain bugs and does not work in all possible corner cases.

I have access to developer accounts on OneLogin and Auth0. There is no
usable, permanent free tier on Okta, so the Okta support has fallen
behind (it should be functional but not all features may be supported).


(C) 2020, 2021 Henning Schmiedehausen


### Building

As with most golang software, building is straightforward:

```bash
$ git clone git@github.com:hgschmie/ofa
$ cd ofa
$ go install
```

### How to help as a developer / user:

Use the tool! If you are using AWS with Okta or OneLogin, it should work out of the box.

Any bug reports, feedback, pull requests are welcome, please use [the github issue tracker](https://github.com/hgschmie/ofa/issues) to report them.

At this point, the tool is good enough for me to use so I will only add new features if users ask for them or if I need them myself.

I implement what customers and myself need; this used to be Okta in the past and OneLogin now.

### If you work for an IdP vendor

Feel free to reach out to me to get your service supported by `ofa`.

- If you work for Okta:
  - I am lacking a working account that can install applications (the developer accounts don't and the trial accounts expire and I don't want to play catchup
  all the time).
  - No one could tell me whether [parsing a HTML page] (https://developer.okta.com/docs/guides/session-cookie/overview/#retrieving-a-session-cookie-via-openid-connect-authorization-endpoint) is really the only way to get at the SAML Assertion with an access token. I found similar code in other tools but it seems less than ideal.
- If you work for Auth0:
  - https://community.auth0.com/t/exchange-a-bearer-token-for-a-saml-assertion/59354 is a hard blocker. I abandoned work on the auth0 code because of it and the lack of community response

#### NOTE ABOUT MACOS CODE SIGNING

ofa release binaries for MacOS are (for now) not signed. Starting with MacOS 10.15, MacOS will complain (and refuse to open the binary). Go to "Security & Privacy" in preferences, choose the "General" tab and click on "Allow anyway" the first time that this happens. Afterwards, ofa runs normally. See https://github.com/hashicorp/terraform/issues/23033#issuecomment-542302933 for more details.

I currently have no way to sign the released binaries for MacOS and I have no desire to shell out money for developer tools unless I use them all the time.
