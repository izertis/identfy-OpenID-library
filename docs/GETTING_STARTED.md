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

For the use of the library only Node with a version equal or higher than 22 is required.

### Test execution

The library comes with a battery of tests written with Jest. To run them you will have to install the corresponding dependencies and run the tests with `npm run test`.

## Overview of the code

### Capabilities
- Creation of authorization requests with different `response_type` (code, id_token and vp_token).
- Validation of authorization requests.
- Issuance of access tokens
  - Support for `grant_type` "authorization_code".
  - Support for `grant_type` "pre-authorize_code".
- Issuance of W3C credentials for version 1 and 2 of the data model (OID4VCI Draft 11).
  - Verification of DIDs for control proofs.
  - Support for in-time flow.
  - Support for deferred flow.
- Verification of W3C Credentials (OID4VP Draft 14).

### State management

The library requires a StateManager interface implementation to handle the protocol-derived state. This interface simulates a key-value store, but the actual implementation is left to the user. A basic in-memory version is included for testing, but it's not suitable for production.

State tracking is essential, as protocol operations must follow a strict order. For example, an ID Token cannot be verified unless it was previously requested.

### Algorithms and object signature

The library does not implement or support any cryptographic algorithms. Instead, this responsibility is left to the user. Consequently, the user is given the freedom to choose the solution that best suits the needs of the use case.

### Builders
The library defines multiple builders that can be used to generate authorization requests, `credential offers`, authorization details and also the metadata of a credential issuer. There is also a step builder that can be used to create an instance of the RP.

### Relying Party

To manage the OpenID process for issuers or any other entity interested in authorization/authentication, the OpenIDRelyingParty class is defined.

When instantiating this class, the user must provide:
  - Authorization server metadata that defines the OpenID configuration.
  - A DidResolver instance to resolve DIDs to their corresponding DID Documents.
  - A signing callback used to sign the tokens or data required during the protocol.
  - A default holder metadata object, which serves as a base configuration for all Holder Wallets initiating requests. This metadata is dynamically overridden by the actual data provided by each Holder.
  - A scope verification flag, which enables or disables verification of the scope parameter against the scopes_supported declared in the authorization server metadata.
  - A state manager, responsible for managing and storing nonces.
  - A subject comparison function, used to verify if two identifiers (typically DIDs) refer to the same subject.
  - A general configuration object, defining expiration times for the tokens involved in the flow.
  - Optionally, several custom verification callbacks can be provided:
      - To validate the issuer state parameter.
      - To check the authorization details of the request.
      - To validate credentials during VP presentation based on custom business logic.
      - To validate a pre-authorization code when using the pre-authorized flow.

By allowing default metadata and flexible callback injection, this class supports multiple use cases while simplifying the implementation for relying parties.

It is recomended to read the tests and the provided documentation for each method.

```ts
const rp = new OpenIdRPStepBuilder(
    {
      ...generateDefaultAuthorisationServerMetadata("https://issuer"),
      grant_types_supported: [
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "authorization_code"
      ]
    }
  )
    .withPreAuthCallback(async (clientId, preCode, pin) => { // Used to validate pre-auth codes
      if (preCode !== "123" || pin !== "444") {
        return Result.Err(new Error("Invalid"));
      }
      return Result.Ok(holderDid);
    })
    .withVpCredentialExternalVerification(async (vc, dm, key) => {
      return Result.Ok(null); // Used to validate the claims data in VPs
    })
    .setDefaultHolderMetadata({
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
    })
    .withDidResolver(new Resolver(getResolver()))
    .withTokenSignCallback((payload, algs) => {
      return signCallback(payload, algs);
    })
    .withStateManager(new MemoryStateManager())
    .build();
```

The Relying Party class currently allows the following:
- Validate Base Authz Request (AuthzRequest with "code" as response_type)
- Generate ID Token Request
- Validate ID Token Response
- Generate VP Token Request
- Validate VP Token Response
- Generate authorization code.
- Validate Token Request
- Generate Token Response

#### Verify Authz request with "code" as "response_type"
```ts
let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
  authzRequest, // Authz Request from the client
);
```

#### Create ID Token Request
In order to do so, first we need to verify an Authz Request as indicated in the previous example
```ts

// Create ID Token Request
const idTokenRequest = await rp.createIdTokenRequest(
  verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
  verifiedAuthzRequest.authzRequest.client_id,
  authServerUrl + "/direct_post",
  {
    type: "Issuance",
    verifiedBaseAuthzRequest: verifiedAuthzRequest,
  }
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
const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
  idTokenResponse, // ID Token response sent by a user
);
```
The method also generates an authorization code, that can be exchange for an access token in the next step.

#### Generate AccessToken / Token Response
```ts
// Create Token Request
const tokenRequest: TokenRequest = {
  grant_type: "authorization_code",
  client_id: holderDid,
  code_verifier: codeVerifier,
  code: verifiedIdTokenResponse.authzCode
};
// Create Token Response
const _tokenResponse = await rp.generateAccessToken(
  tokenRequest,
  false,
  authServerUrl,
  authServerJWK
);
```

The method support both the authorization_code grant type and also, the pre-authorize one. However, only the first one is avaible by default. In order to be able to use pre-authorization codes, the user must specify it during the building phase of the RP using the setp builder, which will require a callback to be provided to redeem these codes.

#### Create VP Token Request
```ts
const vpRequest = await rp.createVpTokenRequest(
  verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
  verifiedAuthzRequest.authzRequest.client_id,
  authServerUrl + "/direct_post",
  signCallback
);
```
The call accepts the following additional parameters:
```ts
export type CreateVpTokenRequestOptionalParams = {
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
  scope?: string;
  /**
   * The presentation definition to include in the JWT
   */
  presentation_definition?: DIFPresentationDefinition;
  /**
   * The URI in which the presentation definition can be retrieved
   */
  presentation_definition_uri?: string
}
```

#### Verify VP Token Response
```ts
const presentationDefinition = getPresentationDefinition();
await rp.verifyVpTokenResponse(
  vpResponse,
  presentationDefinition,
);
```

### VC Issuer
#### CredentialDataManager
The CredentialDataManager is a pluggable abstraction used internally by the W3CVcIssuer class to retrieve all data necessary to issue a Verifiable Credential (VC). It allows the issuer component to remain decoupled from the logic responsible for:
- Extracting or generating the credentialSubject data.
- Determining whether a VC should be issued immediately or deferred.
- Managing deferred credential flows via acceptance tokens.
- Optionally resolving the actual subject identifier (e.g. via a DID URL).

The user needs to give an implementation of this class to the VC Issuer component in order to generate VCs.

#### VC Issuer Class
The W3CVcIssuer class is responsible for issuing W3C Verifiable Credentials using either immediate (in-time) or deferred flows, aligned with the OID4VCI specification.

It integrates with the CredentialDataManager component to retrieve subject-specific credential data and exposes a simple interface to validate access tokens and issue credentials.

```js
const vcIssuer = new W3CVcIssuer(
  metadata,                // IssuerMetadata
  didResolver,             // Resolver instance for DIDs
  issuerDid,               // DID string of the issuer
  signCallback,            // Function that signs the VC
  stateManager,            // StateManager used for nonce handling
  credentialDataManager,   // Instance of CredentialDataManager
  vcTypesContextMap?       // Optional: type-to-context mapping for dynamic context injection
)
```

To issue a VC using the InTime flow:

```js
const accessToken = await issuer.verifyAccessToken(token, publicKey);
const response = await issuer.generateCredentialResponse(accessToken, credentialRequest, W3CDataModel.V1);
```

To exchange a deferred code for a VC:
```js
const response = await issuer.exchangeAcceptanceTokenForVc(deferredToken, W3CDataModel.V2);
```

## Code of contribution

Read please the [contribution documentation](../CONTRIBUTING.md)