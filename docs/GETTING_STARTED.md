<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./img/identfy-logo-dark.svg">
      <source media="(prefers-color-scheme: light)" srcset="./img/identfy-logo-light.svg">
      <img alt="identfy" src="./img/identfy.png" width="350" style="max-width: 100%;">
    </picture>
</p>

<p align="center">
  <h4>
    An all-in-one solution to take control of your digital identity
  </h4>
</p>

<br/>

#  identfy OpenID library

## Build

For the use of the library only Node with a version equal or higher than 16 is required.

### Test execution

The library comes with a battery of tests written with Mocha and Chai. To run them you will have to install the corresponding dependencies and transpile the TS code to JS with `npm run build`. Then you can run the tests with `npm run test`. It is also possible to do both steps with the same command `npm run build_and_test`.


## Overview of the code

### Capabilities
- Creation of authorization requests with different `response_type` (code and id_token).
- Validation of authorization requests.
- Issuance of access tokens
  - Support for `grant_type` "authorization_code".
  - Support for `grant_type` "pre-authorize_code".
- Issuance of W3C credentials for version 1 and 2 of the data model.
  - Verification of DIDs for control proofs.
  - Support for in-time flow.
  - Support for deferred flow.

### State management

The library does not manage any state, nor does it present any abstract interface or other elements that allow it to manage state indirectly. Instead, the user must provide the functionality related to state management by providing callbacks where appropriate.

### Algorithms and object signature

The library does not implement or support any cryptographic algorithms. Instead, this responsibility is left to the user. Consequently, the user is given the freedom to choose the solution that best suits the needs of the use case.

### Builders
The library defines multiple builders that can be used to generate authorization requests, `credential offers`, authorization details and also the metadata of a credential issuer.

### Relying Party

To manage the OpenID process for issuers or any other entity interested in authorization/authentication, the ***OpenIdRelyingParty*** class is defined. For its construction, the user should provide the metadata of the authorization service, an instance of ***DidResolver*** and a callback that allows to obtain the default metadata from the clients. The latter allows the metadata to be bound to the use case, eliminating the need for clients to specify it in full. In practice, the metadata implicitly specified by the user will be combined with the default metadata, the former prevailing over the latter.


```ts
const rp = new OpenIDRelyingParty(
    async () => {
      return {
        "authorization_endpoint": "openid:",
        "response_types_supported": ["vp_token", "id_token"],
        "vp_formats_supported": {
          "jwt_vp": {
            "alg_values_supported": ["ES256"]
          },
          "jwt_vc": {
            "alg_values_supported": ["ES256"]
          }
        },
        "scopes_supported": ["openid"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "subject_syntax_types_supported": [
          "urn:ietf:params:oauth:jwk-thumbprint",
          "did:key:jwk_jcs-pub"
        ],
        "id_token_types_supported": ["subject_signed_id_token"]
      }
    },
    {
      ...generateDefaultAuthorisationServerMetadata("https://issuer"),
      grant_types_supported: ["authorization_code", "pre-authorised_code"]
    },
    new Resolver(getResolver())
  );
```

The Relying Party class currently allows the following:
- Validate Base Authz Request (AuthzRequest with "code" as response_type)
- Generate ID Token Request
- Validate ID Token Response
- Generate authorization code.
- Validate Token Request
- Generate Token Response

#### Verify Authz request with "code" as "response_type"
```ts
let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
  authzRequest, // Request from client
  {
    // Optional verification callback
    authzDetailsVerifyCallback: async (details) => {
      if (details.types && !details.types.includes("TestVc")) {
        return { valid: false, error: "Unssuported VC Type" };
      }
      return { valid: true };
    }
  }
);
```
It is also possible to supply two additional callbacks to check the scope value and the `issuer_state` value.

#### Create ID Token Request
```ts
// Example with jose npm package
const signCallback = async (payload: JwtPayload, _supportedAlgs?: JWA_ALGS[]) => {
  const header = {
    alg: "ES256",
    kid: `${authServerDid}#${authServerKid}`
  };
  const keyLike = await importJWK(authServerJWK);
  return await new SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt()
    .sign(keyLike);
};

const idTokenRequest = await rp.createIdTokenRequest(
  verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
  verifiedAuthzRequest.authzRequest.client_id,
  authServerUrl + "/direct_post",
  signCallback
);
```

The call accepts the following optional parameters:
```ts
export type CreateIdTokenRequestOptionalParams = {
  /**
   * Response mode to specify in the ID Token
   * @defaultValue "direct_post" 
   */
  responseMode?: AuthzResponseMode;
  /**
   * Additional payload to include in the JWT 
   */
  additionalPayload?: Record<string, any>;
  /**
   * The state to indicate in the JWT
   */
  state?: string;
  /**
   * The nonce to indicate in the JWT.
   * @defaultValue UUID randomly generated
   */
  nonce?: string;
  /**
   * The expiration time of the JWT. Must be in seconds
   * @defaultValue 1 hour
   */
  expirationTime?: number;
  /**
   * The scope to include in the JWT
   */
  scope?: string
};
```

#### Verify ID Token Response
```ts
const _verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
  idTokenResponse,
  async (_header, payload, didDocument) => {
    if (!payload.nonce || payload.nonce !== idTokenRequest.requestParams.nonce!) {
      return { valid: false, error: "Invalid nonce" };
    }
    if (didDocument.id !== holderDid) { // HolderDID being the expected DID
      return { valid: false, error: "Unkown client id" }
    }
    return { valid: true }
  }
);
```
The method does not define any optional parameters.

#### Generate AccessToken / Token Response
```ts
const _tokenResponse = await rp.generateAccessToken(
  tokenRequest,
  false, // Indicate if the response should include an ID Token
  signCallback,
  authServerUrl,
  {
    authorizeCodeCallback: async (_clientId, code) => {
      if (code === "1453") {
        return { valid: true };
      }
      return { valid: false, error: "Invalid authz code" };
    },
    codeVerifierCallback: async (_clientId, codeVerifier) => {
      if (!codeVerifier || !await verifyChallenge(codeVerifier, authzRequest.code_challenge!)) {
        return { valid: false, error: "Invalid code_verifier" };
      }
      return { valid: true }
    },
  }
);
```

The method enables several optional parameters that must be supplied depending on the `grant_type` supported:
- `authorization_code`: Must supply a callback for the verification of the code itself and a second one for the verification of the PKCE Challenge that must have been delivered by the user in a previous authorization request.
- `pre-authorize_code`: It must supply a callback for the verification of the code itself that additionally receives the PIN sent by the user.

## Code of contribution

Read please the [contribution documentation](../CONTRIBUTING.md)