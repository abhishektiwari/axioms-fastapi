Issuer Configuration
====================

This page provides configuration examples for popular OAuth2/OIDC authorization servers.

AWS Cognito
-----------

Amazon Cognito User Pools issue JWT tokens with the issuer URL following this pattern:

.. seealso::
   * `AWS Cognito User Pools Documentation <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html>`_
   * `Verifying a JSON Web Token <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html>`_

.. code-block:: bash

   AXIOMS_AUDIENCE=your-api-audience
   AXIOMS_ISS_URL=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefg
   AXIOMS_JWKS_URL=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefg/.well-known/jwks.json

**Parameters to replace:**

* ``us-east-1`` - Your AWS region (e.g., us-west-2, eu-west-1)
* ``us-east-1_abcdefg`` - Your Cognito User Pool ID

**Finding your User Pool ID:**

1. Open the AWS Cognito console
2. Navigate to your User Pool
3. The Pool ID is displayed on the General settings page

**Example JWT Token from Cognito:**

.. code-block:: json

   {
     "sub": "1234567890",
     "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefg",
     "aud": "your-api-audience",
     "token_use": "access",
     "scope": "openid profile email",
     "auth_time": 1735686000,
     "exp": 1735689600,
     "iat": 1735686000
   }

Auth0
-----

Auth0 tenants have issuer URLs based on your tenant domain:

.. seealso::
   * `Auth0 Access Token Overview <https://auth0.com/docs/secure/tokens>`_
   * `Auth0 Custom Domains <https://auth0.com/docs/customize/custom-domains>`_
   * `Auth0 Tenant Settings <https://auth0.com/docs/get-started/tenant-settings>`_

.. code-block:: bash

   AXIOMS_AUDIENCE=https://your-api.example.com
   AXIOMS_ISS_URL=https://your-tenant.auth0.com/
   AXIOMS_JWKS_URL=https://your-tenant.auth0.com/.well-known/jwks.json

**Parameters to replace:**

* ``your-tenant`` - Your Auth0 tenant domain
* ``your-api.example.com`` - Your API identifier configured in Auth0

**Regional Deployments:**

For Auth0 tenants in specific regions:

.. code-block:: bash

   # US region
   AXIOMS_ISS_URL=https://your-tenant.us.auth0.com/
   AXIOMS_JWKS_URL=https://your-tenant.us.auth0.com/.well-known/jwks.json

   # EU region
   AXIOMS_ISS_URL=https://your-tenant.eu.auth0.com/
   AXIOMS_JWKS_URL=https://your-tenant.eu.auth0.com/.well-known/jwks.json

   # Australia region
   AXIOMS_ISS_URL=https://your-tenant.au.auth0.com/
   AXIOMS_JWKS_URL=https://your-tenant.au.auth0.com/.well-known/jwks.json

**Custom Domains:**

If you're using a custom domain in Auth0:

.. code-block:: bash

   AXIOMS_ISS_URL=https://login.yourdomain.com/
   AXIOMS_JWKS_URL=https://login.yourdomain.com/.well-known/jwks.json

**Example JWT Token from Auth0:**

.. code-block:: json

   {
     "sub": "auth0|1234567890",
     "iss": "https://your-tenant.auth0.com/",
     "aud": "https://your-api.example.com",
     "scope": "openid profile email read:data",
     "azp": "client-id",
     "exp": 1735689600,
     "iat": 1735686000
   }

Okta
----

Okta authorization servers use URLs based on your Okta domain and authorization server ID:

.. seealso::
   * `Okta OAuth 2.0 Overview <https://developer.okta.com/docs/reference/api/oidc/>`_
   * `Okta Authorization Servers <https://developer.okta.com/docs/concepts/auth-servers/>`_
   * `Validate Access Tokens <https://developer.okta.com/docs/guides/validate-access-tokens/>`_
   * `Find your Okta domain <https://developer.okta.com/docs/guides/find-your-domain/>`_

**Default Authorization Server:**

.. code-block:: bash

   AXIOMS_AUDIENCE=api://default
   AXIOMS_ISS_URL=https://your-domain.okta.com/oauth2/default
   AXIOMS_JWKS_URL=https://your-domain.okta.com/oauth2/default/v1/keys

**Custom Authorization Server:**

.. code-block:: bash

   AXIOMS_AUDIENCE=api://your-audience
   AXIOMS_ISS_URL=https://your-domain.okta.com/oauth2/aus1234567890abcde
   AXIOMS_JWKS_URL=https://your-domain.okta.com/oauth2/aus1234567890abcde/v1/keys

**Parameters to replace:**

* ``your-domain`` - Your Okta domain (e.g., dev-123456.okta.com)
* ``aus1234567890abcde`` - Your custom authorization server ID
* ``your-audience`` - Your API audience identifier

**Okta Preview Domains:**

For Okta preview environments:

.. code-block:: bash

   AXIOMS_ISS_URL=https://your-domain.oktapreview.com/oauth2/default
   AXIOMS_JWKS_URL=https://your-domain.oktapreview.com/oauth2/default/v1/keys

**Finding your Authorization Server ID:**

1. Log in to your Okta admin console
2. Navigate to Security → API
3. Click on your authorization server
4. The ID is shown in the URL or Settings tab

**Example JWT Token from Okta:**

.. code-block:: json

   {
     "sub": "00u1234567890abcde",
     "iss": "https://your-domain.okta.com/oauth2/default",
     "aud": "api://default",
     "scp": ["openid", "profile", "email"],
     "groups": ["Everyone", "Developers"],
     "exp": 1735689600,
     "iat": 1735686000,
     "cid": "0oa1234567890abcde"
   }

Microsoft Entra (Azure AD)
--------------------------

Microsoft Entra ID (formerly Azure Active Directory) uses tenant-based issuer URLs:

.. seealso::
   * `Microsoft identity platform access tokens <https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens>`_
   * `Validate tokens <https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-tokens>`_
   * `OpenID Connect on the Microsoft identity platform <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc>`_
   * `Find your Azure AD tenant ID <https://learn.microsoft.com/en-us/entra/fundamentals/how-to-find-tenant>`_

**V2.0 Endpoint (Recommended):**

.. code-block:: bash

   AXIOMS_AUDIENCE=api://your-client-id
   AXIOMS_ISS_URL=https://login.microsoftonline.com/your-tenant-id/v2.0
   AXIOMS_JWKS_URL=https://login.microsoftonline.com/your-tenant-id/discovery/v2.0/keys

**V1.0 Endpoint:**

.. code-block:: bash

   AXIOMS_AUDIENCE=https://your-api.example.com
   AXIOMS_ISS_URL=https://sts.windows.net/your-tenant-id/
   AXIOMS_JWKS_URL=https://login.microsoftonline.com/your-tenant-id/discovery/keys

**Parameters to replace:**

* ``your-tenant-id`` - Your Azure AD tenant ID (GUID format)
* ``your-client-id`` - Your application's client ID (GUID format)

**Multi-Tenant Applications:**

For multi-tenant applications, you may need to accept tokens from multiple tenants:

.. code-block:: bash

   # Use 'common', 'organizations', or 'consumers'
   AXIOMS_ISS_URL=https://login.microsoftonline.com/common/v2.0
   AXIOMS_JWKS_URL=https://login.microsoftonline.com/common/discovery/v2.0/keys

.. warning::
   When using ``common``, ``organizations``, or ``consumers``, token validation will accept tokens from ANY tenant. Make sure to implement additional validation logic in your application to verify the tenant ID (``tid`` claim) matches your expected tenants.

**Azure Government Cloud:**

.. code-block:: bash

   AXIOMS_ISS_URL=https://login.microsoftonline.us/your-tenant-id/v2.0
   AXIOMS_JWKS_URL=https://login.microsoftonline.us/your-tenant-id/discovery/v2.0/keys

**Azure China Cloud:**

.. code-block:: bash

   AXIOMS_ISS_URL=https://login.chinacloudapi.cn/your-tenant-id/v2.0
   AXIOMS_JWKS_URL=https://login.chinacloudapi.cn/your-tenant-id/discovery/v2.0/keys

**Finding your Tenant ID:**

1. Log in to Azure Portal
2. Navigate to Azure Active Directory
3. The Tenant ID is displayed on the Overview page

**Example JWT Token from Microsoft Entra (V2.0):**

.. code-block:: json

   {
     "sub": "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
     "iss": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0",
     "aud": "api://abcdefgh-1234-1234-1234-123456789012",
     "scp": "user.read email profile",
     "roles": ["Admin", "User"],
     "tid": "12345678-1234-1234-1234-123456789012",
     "exp": 1735689600,
     "iat": 1735686000,
     "nbf": 1735686000
   }

Generic OIDC Provider
---------------------

For any OAuth2/OIDC compliant provider, you can use the OpenID Connect discovery endpoint to find the correct URLs:

.. seealso::
   * `OpenID Connect Discovery Specification <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
   * `OAuth 2.0 Authorization Framework <https://datatracker.ietf.org/doc/html/rfc6749>`_
   * `JSON Web Token (JWT) Specification <https://datatracker.ietf.org/doc/html/rfc7519>`_

**Discovery Endpoint:**

Most OIDC providers expose a discovery endpoint at:

.. code-block:: text

   https://your-auth-server.com/.well-known/openid-configuration

**Using the Discovery Document:**

1. Fetch the discovery document:

   .. code-block:: bash

      curl https://your-auth-server.com/.well-known/openid-configuration

2. Look for these fields in the JSON response:

   * ``issuer`` - Use this for ``AXIOMS_ISS_URL``
   * ``jwks_uri`` - Use this for ``AXIOMS_JWKS_URL``

**Example Discovery Document Response:**

.. code-block:: json

   {
     "issuer": "https://your-auth-server.com",
     "authorization_endpoint": "https://your-auth-server.com/oauth2/authorize",
     "token_endpoint": "https://your-auth-server.com/oauth2/token",
     "jwks_uri": "https://your-auth-server.com/.well-known/jwks.json",
     "response_types_supported": ["code", "token"],
     "subject_types_supported": ["public"],
     "id_token_signing_alg_values_supported": ["RS256"]
   }

**Configuration:**

.. code-block:: bash

   AXIOMS_AUDIENCE=your-api-audience
   AXIOMS_ISS_URL=https://your-auth-server.com
   AXIOMS_JWKS_URL=https://your-auth-server.com/.well-known/jwks.json

Testing Your Configuration
---------------------------

After configuring your issuer URLs, verify the setup:

.. seealso::
   * `JWT.io - JWT Debugger <https://jwt.io>`_ - Decode and inspect JWT tokens
   * `JSON Web Key Sets (JWKS) <https://datatracker.ietf.org/doc/html/rfc7517>`_ - JWKS specification

1. **Decode a JWT token** from your provider using `jwt.io <https://jwt.io>`_

2. **Verify the issuer claim** matches your ``AXIOMS_ISS_URL``:

   .. code-block:: json

      {
        "iss": "https://your-configured-issuer.com",
        ...
      }

3. **Check JWKS endpoint** is accessible:

   .. code-block:: bash

      curl https://your-jwks-url.com/.well-known/jwks.json

   Should return JSON with public keys:

   .. code-block:: json

      {
        "keys": [
          {
            "kty": "RSA",
            "kid": "key-id-1",
            "use": "sig",
            "n": "...",
            "e": "AQAB"
          }
        ]
      }

4. **Test authentication** with a sample API request:

   .. code-block:: bash

      curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
           http://localhost:8000/api/protected

Troubleshooting
---------------

**Common Issues:**

Invalid Issuer
^^^^^^^^^^^^^^

If you get an "Invalid issuer" error:

* Ensure ``AXIOMS_ISS_URL`` exactly matches the ``iss`` claim in your token (including trailing slashes)
* Check for http vs https differences
* Verify tenant IDs and domains are correct

JWKS Not Found
^^^^^^^^^^^^^^

If public keys cannot be fetched:

* Verify ``AXIOMS_JWKS_URL`` is accessible from your server
* Check firewall rules allow outbound HTTPS connections
* Ensure the URL returns valid JSON with ``keys`` array

Token Expired
^^^^^^^^^^^^^

If tokens are always expired:

* Check server time is synchronized (use NTP)
* Verify token ``exp`` claim is in the future
* Consider clock skew between issuer and your server

Audience Mismatch
^^^^^^^^^^^^^^^^^

If you get "Invalid audience" errors:

* Ensure ``AXIOMS_AUDIENCE`` matches the ``aud`` claim in your token exactly
* Some providers require audience to be an array - check your token
* Verify you're requesting the correct audience when obtaining tokens

See Also
--------

* :doc:`examples` - Usage examples for different authorization patterns
* :doc:`api` - Full API reference
* `OpenID Connect Discovery Specification <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
