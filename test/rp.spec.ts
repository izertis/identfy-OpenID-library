import { assert, expect } from "chai";
import { OpenIDReliyingParty } from "../src/core/rp/index.js";
import {
  AuthzDetailsBuilder,
  AuthzRequestBuilder,
  CredentialOfferBuilder,
  IdTokenRequest,
  IdTokenResponse,
  JWA_ALGS,
  TokenRequest,
  alwaysAcceptVerification,
  decodeToken,
  generateChallenge,
  generateDefaultAuthorisationServerMetadata
} from "../src/index.js";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { Resolver } from "did-resolver";
import { SignJWT, importJWK } from "jose";
import { JwtPayload } from "jsonwebtoken";
import { verifyChallenge } from "pkce-challenge";

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

describe("Reliying Party tests", async () => {
  const rp = new OpenIDReliyingParty(
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
      grant_types_supported: ["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    },
    new Resolver(getResolver()),
    alwaysAcceptVerification
  );
  context("authorization_code response type with ID Token", async () => {
    it("It should successfully emit an AccessToken", async () => {
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
          {
            authzDetailsVerifyCallback: async (details) => {
              if (details.types && !details.types.includes("TestVc")) {
                return { valid: false, error: "Unssuported VC Type" };
              }
              return { valid: true };
            }
          }
        );
        // Create ID Token Request
        const idTokenRequest = await rp.createIdTokenRequest(
          verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
          verifiedAuthzRequest.authzRequest.client_id,
          authServerUrl + "/direct_post",
          signCallback
        );
        // Create ID Token Response
        const idTokenResponse = await generateIdToken(idTokenRequest);
        // Verify ID Token Response
        const _verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
          idTokenResponse,
          async (_header, payload, didDocument) => {
            if (!payload.nonce || payload.nonce !== idTokenRequest.requestParams.nonce!) {
              return { valid: false, error: "Invalid nonce" };
            }
            if (didDocument.id !== holderDid) {
              return { valid: false, error: "Unkown client id" }
            }
            return { valid: true }
          }
        );
        // Create Authz Response
        const authzResponse = rp.createAuthzResponse(
          authzRequest.redirect_uri,
          "1453",
          authzRequest.state
        );
        // Create Token Request
        const tokenRequest: TokenRequest = {
          grant_type: "authorization_code",
          client_id: holderDid,
          code_verifier: codeVerifier,
          code: authzResponse.code
        };
        // Create Token Response
        const _tokenResponse = await rp.generateAccessToken(
          tokenRequest,
          false,
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
      }).to.not.throw();
    });
    it("Should detect Authz with incorrect details", async () => {
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
      try {
        await rp.verifyBaseAuthzRequest(
          authzRequest,
          {
            authzDetailsVerifyCallback: async (_details) => {
              return { valid: false };
            }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should detect Authz with incorrect scope", async () => {
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
      try {
        await rp.verifyBaseAuthzRequest(
          authzRequest,
          {
            scopeVerifyCallback: async (_scope) => {
              return { valid: false };
            }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should reject Authz request with no issuer_state", async () => {
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
      try {
        await rp.verifyBaseAuthzRequest(
          authzRequest,
          {
            issuerStateVerifyCallback: async (_scope) => {
              return { valid: true };
            }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should reject ID Token with incorrect signature", async () => {
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
      try {
        await rp.verifyIdTokenResponse(
          {
            id_token: jwt
          },
          async (_header, _payload, didDocument) => {
            if (didDocument.id !== holderDid) {
              return { valid: false, error: "Unkown client id" }
            }
            return { valid: true }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should reject ID Token with incorrect kid", async () => {
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
      try {
        await rp.verifyIdTokenResponse(
          {
            id_token: idToken
          },
          async (_header, _payload, didDocument) => {
            if (didDocument.id !== holderDid) {
              return { valid: false, error: "Unkown client id" }
            }
            return { valid: true }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should reject ID Token with unsupported DID Method", async () => {
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
      try {
        await rp.verifyIdTokenResponse(
          {
            id_token: idToken
          },
          async (_header, _payload, didDocument) => {
            if (didDocument.id !== holderDid) {
              return { valid: false, error: "Unkown client id" }
            }
            return { valid: true }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should reject Token Request with unssuported Grant", async () => {
      // Create Token Request
      const tokenRequest: TokenRequest = {
        grant_type: "vp_token",
        client_id: holderDid
      };
      try {
        // Create Token Response
        await rp.generateAccessToken(
          tokenRequest,
          false,
          signCallback,
          authServerUrl,
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should reject Token Request with invalid authz code", async () => {
      // Create Token Request
      const tokenRequest: TokenRequest = {
        grant_type: "vp_token",
        client_id: holderDid,
        code_verifier: "test",
        code: "123"
      };
      try {
        // Create Token Response
        await rp.generateAccessToken(
          tokenRequest,
          false,
          signCallback,
          authServerUrl,
          {
            codeVerifierCallback: async (_id, _codeVerifier) => {
              return { valid: true };
            },
            authorizeCodeCallback: async (_id, code) => {
              return { valid: false };
            }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
    it("Should reject Token Request with invalid cove_verifier", async () => {
      // Create Token Request
      const tokenRequest: TokenRequest = {
        grant_type: "vp_token",
        client_id: holderDid,
        code_verifier: "test",
        code: "123"
      };
      try {
        // Create Token Response
        await rp.generateAccessToken(
          tokenRequest,
          false,
          signCallback,
          authServerUrl,
          {
            codeVerifierCallback: async (_id, _codeVerifier) => {
              return { valid: false };
            },
            authorizeCodeCallback: async (_id, code) => {
              return { valid: true };
            }
          }
        );
        assert.fail("Should have thrown");
      } catch (_error: any) { }
    });
  });
  it("Access Token generation with pre-auth code", async () => {
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
    try {
      await rp.generateAccessToken(
        tokenRequest,
        false,
        signCallback,
        authServerUrl,
        {
          preAuthorizeCodeCallback: async (_clientId, code, pin) => {
            if (code !== "123" || pin !== "444") {
              return { error: "Invalid pre-auth" };
            }
            return { client_id: holderDid };
          }
        }
      );
    } catch (_error: any) {
      assert.fail("AccessToken with preAuth thrown an unexpected exception");
    }
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
