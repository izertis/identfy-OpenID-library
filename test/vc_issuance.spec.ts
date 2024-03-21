import { assert, expect } from "chai";
import { W3CVcIssuer } from "../src/core/credentials/index.js";
import {
  CredentialRequest,
  CredentialResponse,
  CredentialSupportedBuilder,
  W3CDataModel
} from "../src/index.js";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { SignJWT, importJWK } from "jose";

const issuerUrl = "https://issuer";

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
const holderKid = "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KboxCaZdensP4av2bfpZ9kMwQnnjftpb3mEnh2qouVjyWsmdvWQSDKhKTNQN5jgpYLk82ToEcC8tq5gaGQxsH366uEVrwUHWytbghxynS4qNGzaLTQga3qvTYc5NwyuhfCqa";

const issuerJWK = {
  "kty": "EC",
  "d": "ytyKElsW0ZSAUe56jHYxWwMwPdqyp0CYNsD1rv75mTg",
  "use": "sig",
  "crv": "P-256",
  "kid": "D5eDdKiUFRn3_FhmaL4QENmG5asYP95DEdjE93T6o6Q",
  "x": "hasujoWNW2dY100kuBOZBF23NWOlpPPLXOltuiRRe0A",
  "y": "JcdfowA_nhVSjoOMiTJioTYxzIYt58PgwfzxLXq1Fps",
  "alg": "ES256"
}

const issuerDid = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";
const issuerKid = "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";

describe("VC Issuance tests", () => {
  const credentialSupported = [
    new CredentialSupportedBuilder().withTypes(["VcTest"]).build(),
    new CredentialSupportedBuilder().withTypes(["DeferredVc"]).build()
  ];
  const vcIssuer = new W3CVcIssuer(
    {
      credential_issuer: issuerUrl,
      credential_endpoint: issuerUrl + "/credential",
      credentials_supported: credentialSupported
    },
    new Resolver(getResolver()),
    issuerDid,
    async (_format, vc) => {
      const header = {
        alg: "ES256",
        kid: `${issuerDid}#${issuerKid}`
      };
      const keyLike = await importJWK(issuerJWK);
      return await new SignJWT(vc)
        .setProtectedHeader(header)
        .sign(keyLike);
    },
    async (_id) => "nonce",
    async (_types) => {
      return [
        {
          id: "https://test.com/schema",
          type: "CustomType"
        }
      ]
    },
    async (types, _holder) => {
      if (types.includes("VcTest")) {
        return {
          data: {
            test: 123
          }
        }
      } else {
        return {
          deferredCode: "deferred"
        }
      }
    }
  );

  context("In-Time flow", () => {
    it("Should successfully issue a VC", async () => {
      const credentialRequest: CredentialRequest = {
        types: ["VcTest"],
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof()
        }
      };
      try {
        const credentialResponse = await vcIssuer.generateCredentialResponse(
          await generateAccessToken(),
          credentialRequest,
          W3CDataModel.V2,
          {
            tokenVerification: {
              publicKeyJwkAuthServer: issuerJWK,
              tokenVerifyCallback: async (_header, _payload) => {
                return { valid: true }
              }
            }
          }
        );
        expect(credentialResponse.credential).not.to.be.undefined;
        console.log(credentialResponse.credential);
      } catch (_error: any) {
        assert.fail("Should not have thrown");
      }
    });
  });
  context("Deferred flow", () => {
    it("Should successfully issue a VC", async () => {
      const credentialRequest: CredentialRequest = {
        types: ["DeferredVc"],
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof()
        }
      };
      let credentialResponse: CredentialResponse;
      try {
        credentialResponse = await vcIssuer.generateCredentialResponse(
          await generateAccessToken(),
          credentialRequest,
          W3CDataModel.V2,
          {
            tokenVerification: {
              publicKeyJwkAuthServer: issuerJWK,
              tokenVerifyCallback: async (_header, _payload) => {
                return { valid: true }
              }
            }
          }
        );
      } catch (_error: any) {
        assert.fail("Should not have thrown");
      }
      expect(credentialResponse.acceptance_token).not.to.be.undefined;
      try {
        credentialResponse = await vcIssuer.exchangeAcceptanceTokenForVc(
          credentialResponse.acceptance_token!,
          async (token) => {
            if (token === "deferred") {
              return {
                data: {
                  test: 123
                },
                types: ["DeferredVc"],
                format: "jwt_vc_json",
              }
            }
            return { error: "Invalid deferred_code" }
          },
          W3CDataModel.V2
        );
        expect(credentialResponse.credential).not.to.be.undefined;
      } catch (_error: any) {
        assert.fail("Should not have thrown");
      }
    });
  });
});

async function generateAccessToken() {
  const header = {
    alg: "ES256",
    kid: `${issuerDid}#${issuerKid}`
  };
  const keyLike = await importJWK(issuerJWK);
  return await new SignJWT({
    aud: issuerUrl,
    iss: issuerUrl,
    sub: holderDid,
    nonce: "nonce"
  })
    .setProtectedHeader(header)
    .setExpirationTime("15m")
    .sign(keyLike);
}

async function generateProof() {
  const header = {
    typ: "openid4vci-proof+jwt",
    alg: "ES256",
    kid: `${holderDid}#${holderKid}`
  };
  const keyLike = await importJWK(holderJWK);
  return await new SignJWT({ nonce: "nonce" })
    .setProtectedHeader(header)
    .setExpirationTime("15m")
    .setIssuer(holderDid)
    .setAudience(issuerUrl)
    .setIssuedAt()
    .sign(keyLike);
}
