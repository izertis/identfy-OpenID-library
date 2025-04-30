import {
  AuthzDetailsBuilder,
  AuthzRequestBuilder,
  CredentialOfferBuilder,
  IdTokenRequest,
  IdTokenResponse,
  JWA_ALGS,
  TokenRequest,
  decodeToken,
  generateChallenge,
  generateDefaultAuthorisationServerMetadata
} from "../src/index.js";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { Resolver } from "did-resolver";
import { SignJWT, importJWK } from "jose";
import { JwtPayload } from "jsonwebtoken";
import { OpenIdRPStepBuilder } from "@/core/rp/builder.js";
import { MemoryStateManager } from "@/core/state/index.js";
import { Result } from "@/classes";
import { expect, test, describe } from '@jest/globals';

const holderJWK = {
  "kty": "EC",
  "d": "xEHP5NWUHL5tXqrhQlJo_LgaqsFxh75_PPUtatXl-Ek",
  "use": "sig",
  "crv": "P-256",
  "kid": "bUD-_xV9bm71mtDbQ44opyIiN919v3UOvrm8ja0w1as",
  "x": "DZLdhzWtSHJQrsMnnsMgWyok26N172KMEG9McrrG-eE",
  "y": "UmXBOYIICFyQ6cF1R1BDsBuV3xr_E61tl_e6H2LmJw0",
  "alg": "ES256"
};

const holderDid = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KboxCaZdensP4av2bfpZ9kMwQnnjftpb3mEnh2qouVjyWsmdvWQSDKhKTNQN5jgpYLk82ToEcC8tq5gaGQxsH366uEVrwUHWytbghxynS4qNGzaLTQga3qvTYc5NwyuhfCqa";
const holderKid = "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KboxCaZdensP4av2bfpZ9kMwQnnjftpb3mEnh2qouVjyWsmdvWQSDKhKTNQN5jgpYLk82ToEcC8tq5gaGQxsH366uEVrwUHWytbghxynS4qNGzaLTQga3qvTYc5NwyuhfCqa"

const authServerJWK = {
  "kty": "EC",
  "d": "ytyKElsW0ZSAUe56jHYxWwMwPdqyp0CYNsD1rv75mTg",
  "use": "sig",
  "crv": "P-256",
  "kid": "D5eDdKiUFRn3_FhmaL4QENmG5asYP95DEdjE93T6o6Q",
  "x": "hasujoWNW2dY100kuBOZBF23NWOlpPPLXOltuiRRe0A",
  "y": "JcdfowA_nhVSjoOMiTJioTYxzIYt58PgwfzxLXq1Fps",
  "alg": "ES256"
}

const authServerDid = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";
const authServerKid = "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";
const authServerUrl = "https://issuer";

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

describe("Reliying Party tests", () => {
  const rp = new OpenIdRPStepBuilder(
    {
      ...generateDefaultAuthorisationServerMetadata("https://issuer"),
      grant_types_supported: [
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "authorization_code"
      ]
    }
  )
    .withPreAuthCallback(async (clientId, preCode, pin) => {
      if (preCode !== "123" || pin !== "444") {
        return Result.Err(new Error("Invalid"));
      }
      return Result.Ok(holderDid);
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
  describe("authorization_code response type with ID Token", () => {
    test("It should successfully emit an AccessToken", async () => {
      expect(async () => {
        const codeVerifier = "test";
        // Generate AuthzRequest
        const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
          "code",
          holderDid,
          "openid:",
          {},
          await generateChallenge(codeVerifier),
          "ES256"
        ).addAuthzDetails(
          AuthzDetailsBuilder.openIdCredentialBuilder("jwt_vc_json")
            .withTypes(
              ["TestVc"]
            ).build()
        ).build();
        // Verify AuthzRequest
        let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
          authzRequest,
        );
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
        // Create ID Token Response
        const idTokenResponse = await generateIdToken(idTokenRequest);
        // Verify ID Token Response
        const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
          idTokenResponse,
        );
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
          // signCallback,
          authServerUrl,
          authServerJWK
        );
      }).not.toThrow();
    });
    test("Should detect Authz with incorrect details", async () => {
      const newRp = new OpenIdRPStepBuilder(
        generateDefaultAuthorisationServerMetadata("https://issuer")
      )
        .withAuthzDetailsVerification(async (details) => Result.Err(new Error("Invalid")))
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
        .withTokenSignCallback(signCallback)
        .withStateManager(new MemoryStateManager())
        .build();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge("test"),
        "ES256"
      ).addAuthzDetails(
        AuthzDetailsBuilder.openIdCredentialBuilder("jwt_vc_json")
          .withTypes(
            ["TestVc"]
          ).build()
      ).build();
      // Verify AuthzRequest
      await expect(newRp.verifyBaseAuthzRequest(
        authzRequest,
      )).rejects.toThrow();
    });
    test("Should detect Authz with incorrect scope", async () => {
      const newRp = new OpenIdRPStepBuilder(
        generateDefaultAuthorisationServerMetadata("https://issuer")
      )
        .withScopeVerification()
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
        .withTokenSignCallback(signCallback)
        .withStateManager(new MemoryStateManager())
        .build();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid22:",
        {},
        await generateChallenge("test"),
        "ES256"
      ).addAuthzDetails(
        AuthzDetailsBuilder.openIdCredentialBuilder("jwt_vc_json")
          .withTypes(
            ["TestVc"]
          ).build()
      )
      .withScope("openid invalid_scope")
      .build();
      // Verify AuthzRequest
      await expect(newRp.verifyBaseAuthzRequest(
        authzRequest,
      )).rejects.toThrow()
    });
    test("Should reject Authz request with no issuer_state", async () => {
      const newRp = new OpenIdRPStepBuilder(
        generateDefaultAuthorisationServerMetadata("https://issuer")
      )
        .withIssuerStateVerification(async (state) => Result.Ok(null))
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
        .withTokenSignCallback(signCallback)
        .withStateManager(new MemoryStateManager())
        .build();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge("test"),
        "ES256"
      ).addAuthzDetails(
        AuthzDetailsBuilder.openIdCredentialBuilder("jwt_vc_json")
          .withTypes(
            ["TestVc"]
          ).build()
      ).build();
      // Verify AuthzRequest
      await expect(newRp.verifyBaseAuthzRequest(
        authzRequest,
      )).rejects.toThrow();
    });
    test("Should reject ID Token with incorrect signature", async () => {
      const header = {
        alg: "ES256",
        kid: `${holderDid}#${holderKid}`
      };
      const keyLike = await importJWK(holderJWK);
      const idToken = await new SignJWT()
        .setProtectedHeader(header)
        .setIssuer(holderDid)
        .setAudience(authServerUrl)
        .setSubject(holderDid)
        .setExpirationTime("15m")
        .sign(keyLike);
      const { signature } = decodeToken(idToken);
      const jwt = "eyaaaaaaaa.aaaaaaaaa." + signature;
      await expect(rp.verifyIdTokenResponse(
        {
          id_token: jwt
        },
      )).rejects.toThrow();
    });
    test("Should reject ID Token with incorrect kid", async () => {
      const header = {
        alg: "ES256",
        kid: "kid"
      };
      const keyLike = await importJWK(holderJWK);
      const idToken = await new SignJWT()
        .setProtectedHeader(header)
        .setIssuer(holderDid)
        .setAudience(authServerUrl)
        .setSubject(holderDid)
        .setExpirationTime("15m")
        .sign(keyLike);
      await expect(rp.verifyIdTokenResponse(
        {
          id_token: idToken
        },
      )).rejects.toThrow();
    });
    test("Should reject ID Token with unsupported DID Method", async () => {
      const header = {
        alg: "ES256",
        kid: `${holderDid}#${holderKid}`
      };
      const keyLike = await importJWK(holderJWK);
      const idToken = await new SignJWT()
        .setProtectedHeader(header)
        .setIssuer("did:test:123")
        .setAudience(authServerUrl)
        .setSubject(holderDid)
        .setExpirationTime("15m")
        .sign(keyLike);
      await expect(rp.verifyIdTokenResponse(
        {
          id_token: idToken
        },
      )).rejects.toThrow();
    });
    test("Should reject Token Request with unssuported Grant", async () => {
      // Create Token Request
      const tokenRequest: TokenRequest = {
        grant_type: "vp_token",
        client_id: holderDid
      };
      await expect(rp.generateAccessToken(
        tokenRequest,
        false,
        // signCallback,
        authServerUrl,
        authServerJWK
      )).rejects.toThrow();
    });
    test("Should reject Token Request with invalid authz code", async () => {
        const codeVerifier = "test";
        // Generate AuthzRequest
        const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
          "code",
          holderDid,
          "openid:",
          {},
          await generateChallenge(codeVerifier),
          "ES256"
        ).addAuthzDetails(
          AuthzDetailsBuilder.openIdCredentialBuilder("jwt_vc_json")
            .withTypes(
              ["TestVc"]
            ).build()
        ).build();
        let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
          authzRequest,
        );
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
        // Create ID Token Response
        const idTokenResponse = await generateIdToken(idTokenRequest);
        // Verify ID Token Response
        const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
          idTokenResponse,
        );
        // Create Token Request
        const tokenRequest: TokenRequest = {
          grant_type: "authorization_code",
          client_id: holderDid,
          code_verifier: codeVerifier,
          code: "invalid token"
        };
        // Create Token Response
        await expect(rp.generateAccessToken(
          tokenRequest,
          false,
          // signCallback,
          authServerUrl,
          authServerJWK
        )).rejects.toThrow();
    });
    test("Should reject Token Request with invalid code_verifier", async () => {
        const codeVerifier = "INVALID";
        // Generate AuthzRequest
        const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
          "code",
          holderDid,
          "openid:",
          {},
          await generateChallenge("test"),
          "ES256"
        ).addAuthzDetails(
          AuthzDetailsBuilder.openIdCredentialBuilder("jwt_vc_json")
            .withTypes(
              ["TestVc"]
            ).build()
        ).build();
        // Verify AuthzRequest
        let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
          authzRequest,
        );
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
        // Create ID Token Response
        const idTokenResponse = await generateIdToken(idTokenRequest);
        // Verify ID Token Response
        const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
          idTokenResponse,
        );
        // Create Token Request
        const tokenRequest: TokenRequest = {
          grant_type: "authorization_code",
          client_id: holderDid,
          code_verifier: codeVerifier,
          code: verifiedIdTokenResponse.authzCode
        };
        // Create Token Response
        await expect(rp.generateAccessToken(
          tokenRequest,
          false,
          authServerUrl,
          authServerJWK
        )).rejects.toThrow();
    });
  });
  test("Access Token generation with pre-auth code", async () => {
    const credentialOffer = new CredentialOfferBuilder(authServerUrl)
      .withPreAuthGrant(true, "123")
      .addCredential({
        format: "jwt_vc_json",
        types: ["VcTest"]
      })
      .build()
    // Create Token Request
    const tokenRequest: TokenRequest = {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      client_id: holderDid,
      "pre-authorized_code": credentialOffer.grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"]?.["pre-authorized_code"],
      user_pin: "444"
    };
    await expect(rp.generateAccessToken(
      tokenRequest,
      false,
      // signCallback,
      authServerUrl,
      authServerJWK
    )).resolves.not.toThrow();
  });
});

async function generateIdToken(idRequest: IdTokenRequest): Promise<IdTokenResponse> {
  const { payload } = decodeToken(idRequest.request);
  const header = {
    alg: "ES256",
    kid: `${holderDid}#${holderKid}`
  };
  const keyLike = await importJWK(holderJWK);
  const idToken = await new SignJWT({ nonce: idRequest.requestParams.nonce })
    .setProtectedHeader(header)
    .setIssuer(holderDid)
    .setAudience((payload as JwtPayload).iss!)
    .setSubject(holderDid)
    .setExpirationTime("15m")
    .sign(keyLike);
  return {
    id_token: idToken
  }
}
