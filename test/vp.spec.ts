import { assert } from "chai";
import {
  CONTEXT_VC_DATA_MODEL_2,
  CredentialRequest,
  CredentialSupportedBuilder,
  DIFPresentationDefinition,
  DIFPresentationSubmission,
  OpenIDReliyingParty,
  W3CDataModel,
  W3CVcIssuer,
  W3CVerifiableCredentialV2,
  W3CVerifiablePresentation,
  generateDefaultAuthorisationServerMetadata
} from "../src/index.js";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { Resolver } from "did-resolver";
import { SignJWT, importJWK } from "jose";

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

const authServerUrl = "https://issuer";

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

describe("VP Verification tests", async () => {
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
    async (_vc: any, _dmv: any) => {
      return { valid: true }
    }
  )
  let firstVc: string | W3CVerifiableCredentialV2;
  let secondVc: string | W3CVerifiableCredentialV2;
  before(async () => {
    // Generate some credentials to include in the VP
    const credentialSupported = [
      new CredentialSupportedBuilder().withTypes(["VcTestOne"]).build(),
      new CredentialSupportedBuilder().withTypes(["VcTestTwo"]).build()
    ];
    const vcIssuer = new W3CVcIssuer(
      {
        credential_issuer: authServerUrl,
        credential_endpoint: authServerUrl + "/credential",
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
            id: "https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/0x23039e6356ea6b703ce672e7cfac0b42765b150f63df78e2bd18ae785787f6a2",
            type: "FullJsonSchemaValidator2021"
          }
        ]
      },
      async (_types, _holder) => {
        return {
          data: {
            id: holderDid,
            test: 123
          }
        }
      }
    );
    let credentialRequest: CredentialRequest = {
      types: ["VcTestOne"],
      format: "jwt_vc_json",
      proof: {
        proof_type: "jwt",
        jwt: await generateProof()
      }
    };
    let credentialResponse = await vcIssuer.generateCredentialResponse(
      await generateAccessToken(),
      credentialRequest,
      W3CDataModel.V1,
      {
        tokenVerification: {
          publicKeyJwkAuthServer: issuerJWK,
          tokenVerifyCallback: async (_header, _payload) => {
            return { valid: true }
          }
        }
      }
    );
    firstVc = credentialResponse.credential!;
    credentialRequest = {
      types: ["VcTestTwo"],
      format: "jwt_vc_json",
      proof: {
        proof_type: "jwt",
        jwt: await generateProof()
      }
    };
    credentialResponse = await vcIssuer.generateCredentialResponse(
      await generateAccessToken(),
      credentialRequest,
      W3CDataModel.V1,
      {
        tokenVerification: {
          publicKeyJwkAuthServer: issuerJWK,
          tokenVerifyCallback: async (_header, _payload) => {
            return { valid: true }
          }
        }
      },
    );
    secondVc = credentialResponse.credential!;
  });
  context("Succesfull responses", async () => {
    it("Should successfully verify an VP", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      }
      await rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
        ValidNonceCallback
      );
    });
    it("Should successfully verify an VP if more credentials are provided", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string, secondVc as string])
      }
      await rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
        ValidNonceCallback
      );
    });
    it("Should accept empty VP if no claims are requested", async () => {
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors = [];
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.descriptor_map = [];
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([])
      }
      await rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
        ValidNonceCallback
      );
    });
  });
  context("Error responses", async () => {
    it("Should reject an invalid VP if the definition ID of the submission is invalid", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.definition_id = "OtherId";
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      }
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          ValidNonceCallback
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
    it("Should reject a VP if definition has no descriptors and submission does", async () => {
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors = [];
      const presentationSubmission = getPresentationSubmission();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      }
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          ValidNonceCallback
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
    it("Should reject an invalid VP if the input descriptor ID is invalid", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.descriptor_map[1].id = "other-id";
      presentationSubmission.definition_id = "OtherId";
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      }
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          ValidNonceCallback
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
    it("Should reject an invalid VP if not all descriptor are provided", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.descriptor_map.pop();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      }
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          ValidNonceCallback
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
    it("Should reject an invalid VP if not all credentials are provided", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string])
      }
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          ValidNonceCallback
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
    it("Should reject an invalid VP if claim schema is not satisfied", async () => {
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors[1].constraints.fields![1].filter = {
        type: 'string',
      } as any;
      const presentationSubmission = getPresentationSubmission();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      };
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          ValidNonceCallback
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
    it("Should reject an invalid VP if nonce is invalid", async () => {
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors[1].constraints.fields![1].filter = {
        type: 'string',
      } as any;
      const presentationSubmission = getPresentationSubmission();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      };
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          async () => { { return { valid: false } } }
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
    it("Should reject an invalid VP verification callback fail", async () => {
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
        async (_vc: any, _dmv: any) => {
          return { valid: false }
        }
      )
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors[1].constraints.fields![1].filter = {
        type: 'string',
      } as any;
      const presentationSubmission = getPresentationSubmission();
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string, secondVc as string])
      };
      try {
        await rp.verifyVpTokenResponse(
          vpResponse,
          presentationDefinition,
          ValidNonceCallback
        );
      } catch (error: any) {
        return;
      }
      assert.fail(`It should have failed`);
    });
  });
});

function getPresentationDefinition(): DIFPresentationDefinition {
  return {
    id: "definitionId",
    format: { jwt_vc: { alg: ['ES256'] }, jwt_vp: { alg: ['ES256'] } },
    input_descriptors: [
      {
        id: "inputOneId",
        format: { jwt_vc: { alg: ['ES256'] } },
        constraints: {
          fields: [
            {
              path: ['$.vc.type'],
              filter: {
                type: 'array',
                contains: { const: 'VcTestOne' }
              }
            }
          ]
        }
      },
      {
        id: "inputTwoId",
        format: { jwt_vc: { alg: ['ES256'] } },
        constraints: {
          fields: [
            {
              path: ['$.vc.type'],
              filter: {
                type: 'array',
                contains: { const: 'VcTestTwo' }
              }
            },
            {
              path: ['$.vc.credentialSubject.test'],
              filter: {
                type: 'number',
              }
            }
          ]
        }
      }
    ]
  }
}

function getPresentationSubmission(): DIFPresentationSubmission {
  return {
    id: "submissionId",
    definition_id: "definitionId",
    descriptor_map: [
      {
        id: "inputOneId",
        path: "$",
        format: "jwt_vp",
        path_nested: {
          id: "inputOneId",
          format: "jwt_vc",
          path: "$.vp.verifiableCredential[0]"
        }
      },
      {
        id: "inputTwoId",
        path: "$",
        format: "jwt_vp",
        path_nested: {
          id: "inputTwoId",
          format: "jwt_vc",
          path: "$.vp.verifiableCredential[1]"
        }
      }
    ]
  }
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
    .setAudience(authServerUrl)
    .setIssuedAt()
    .sign(keyLike);
}

async function generateVpToken(vc: string[]) {
  const vp: W3CVerifiablePresentation = {
    "@context": CONTEXT_VC_DATA_MODEL_2,
    type: ["VerifiablePresentation"],
    holder: holderDid,
    verifiableCredential: vc
  }
  const header = {
    typ: "openid4vci-proof+jwt",
    alg: "ES256",
    kid: `${holderDid}#${holderKid}`
  };
  const keyLike = await importJWK(holderJWK);
  return await new SignJWT({ vp })
    .setProtectedHeader(header)
    .setExpirationTime("15m")
    .setIssuer(holderDid)
    .setAudience(authServerUrl)
    .setIssuedAt()
    .sign(keyLike);
}

async function generateAccessToken() {
  const header = {
    alg: "ES256",
    kid: `${issuerDid}#${issuerKid}`
  };
  const keyLike = await importJWK(issuerJWK);
  return await new SignJWT({
    aud: authServerUrl,
    iss: authServerUrl,
    sub: holderDid,
    nonce: "nonce"
  })
    .setProtectedHeader(header)
    .setExpirationTime("15m")
    .sign(keyLike);
}

async function ValidNonceCallback() {
  return { valid: true };
}
