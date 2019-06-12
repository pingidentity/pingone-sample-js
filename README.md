# PingOne for Customers OAuth 2.0/OIDC Samples
This repository contains code samples on different languages that will help you to get familiar with OAuth 2 and OpenID Connect protocols that PingOne for Customers supports.

The core functionality here is about how user is delegating access to their identity to the application they're trying to log in to.
Also you will see how the user can delegate access to other protected APIs along side their identity at the same time, making it much simpler for both application developers and end users to manage. 
 
## OAuth 2.0 vs OIDC
**OAuth 2.0** is not an authentication protocol, but OIDC is. <br />
**OAuth 2.0** is about giving this delegated access for use in situations where the user is not present on the connection between the client and the resource being accessed.
The client application then becomes a consumer of the identity API. One major benefit of building authentication on top of authorization in this way is that it allows for management of end-user consent, which is very important in cross-domain identity federation at internet scale.

**OIDC** tells an application who the current user is and whether or not they're present.

## Programming Language Variants
- [**Python**](python)
- [**JavaScript**](javascript)
