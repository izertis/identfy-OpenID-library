import {
  AuthzDetailsBuilder,
  AuthzRequestBuilder,
  CONTEXT_VC_DATA_MODEL_2,
  CredentialDataManager,
  CredentialDataResponse,
  CredentialRequest,
  CredentialSupportedBuilder,
  DIFPresentationDefinition,
  DIFPresentationSubmission,
  DeferredCredentialData,
  IdTokenRequest,
  IdTokenResponse,
  InTimeCredentialData,
  JWA_ALGS,
  TokenRequest,
  W3CDataModel,
  W3CVcIssuer,
  W3CVerifiableCredentialFormats,
  W3CVerifiableCredentialV2,
  W3CVerifiablePresentation,
  decodeToken,
  generateChallenge,
  generateDefaultAuthorisationServerMetadata
} from "../src/index.js";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { Resolver } from "did-resolver";
import { SignJWT, importJWK } from "jose";
import { OpenIdRPStepBuilder } from "@/core/rp/builder.js";
import { Result } from "@/classes";
import { MemoryStateManager } from "@/core/state/index.js";
import { JwtPayload } from "jsonwebtoken";
import { expect, test, describe } from '@jest/globals';

const memoryManager = new MemoryStateManager();
const codeVerifier = "test";

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

const signCallback = async (payload: JwtPayload, _supportedAlgs?: JWA_ALGS[]) => {
  const header = {
    alg: "ES256",
    kid: `${issuerDid}#${issuerKid}`
  };
  const keyLike = await importJWK(issuerJWK);
  return await new SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt()
    .sign(keyLike);
};

describe("VP Verification tests", () => {
  const rp = new OpenIdRPStepBuilder(
    generateDefaultAuthorisationServerMetadata("https://issuer")
  )
    .withVpCredentialExternalVerification(async (vc, dm, key) => {
      return Result.Ok(null);
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
    .withTokenSignCallback(signCallback)
    .withStateManager(memoryManager)
    .build();
  let firstVc: string | W3CVerifiableCredentialV2;
  let secondVc: string | W3CVerifiableCredentialV2;
  beforeAll(async () => {
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
      memoryManager,
      new class extends CredentialDataManager {
        async getCredentialData(types: string[], holder: string): Promise<CredentialDataResponse> {
          if (types.includes("DeferredVc")) {
            return {
              type: "Deferred",
              deferredCode: "1234"
            }
          }
          return {
            type: "InTime",
            data: {
              id: holder,
              test: 123
            },
            schema: {
              id: "https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/0x23039e6356ea6b703ce672e7cfac0b42765b150f63df78e2bd18ae785787f6a2",
              type: "FullJsonSchemaValidator2021"
            },
            metadata: {}
          }
        }
        async deferredExchange(
          _acceptanceToken: string
        ): Promise<
          Result<DeferredCredentialData |
            (InTimeCredentialData & { format: W3CVerifiableCredentialFormats, types: string[] }), Error>
        > {
          return Result.Ok({
            type: "InTime",
            data: {
              id: holderDid,
            },
            schema: {
              id: "https://test.com/schema",
              type: "CustomType"
            },
            metadata: {},
            format: "jwt_vc",
            types: ["CustomType"]
          })
        }
      }
    );
    let tokenResponse = await generateTokenResponse("VcTestOne");
    let credentialRequest: CredentialRequest = {
      types: ["VcTestOne"],
      format: "jwt_vc_json",
      proof: {
        proof_type: "jwt",
        jwt: await generateProof(tokenResponse.c_nonce)
      }
    };
    let verifiedToken = await vcIssuer.verifyAccessToken(tokenResponse.access_token, issuerJWK);

    let credentialResponse = await vcIssuer.generateCredentialResponse(
      verifiedToken,
      credentialRequest,
      W3CDataModel.V1,
    );
    firstVc = credentialResponse.credential!;
    tokenResponse = await generateTokenResponse("VcTestTwo");
    verifiedToken = await vcIssuer.verifyAccessToken(tokenResponse.access_token, issuerJWK);
    credentialRequest = {
      types: ["VcTestTwo"],
      format: "jwt_vc_json",
      proof: {
        proof_type: "jwt",
        jwt: await generateProof(tokenResponse.c_nonce)
      }
    };
    credentialResponse = await vcIssuer.generateCredentialResponse(
      verifiedToken,
      credentialRequest,
      W3CDataModel.V1,
    );
    secondVc = credentialResponse.credential!;
  });

  describe("Succesfull responses", () => {
    test("Should successfully verify an VP", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();

      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string, secondVc as string],
          vpTokenRequest.requestParams.nonce!
        )
      }
      await rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      );
    });
    test("Should successfully verify an VP if more credentials are provided", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken
          ([firstVc as string, secondVc as string, secondVc as string],
            vpTokenRequest.requestParams.nonce!
          )
      }
      await rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      );
    });
    it.skip("Should accept empty VP if no claims are requested", async () => {
      // TODO: Since the change that allows the library the manage the nonces,
      // is not possible to detect the nonce if not format is specified
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors = [];
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.descriptor_map = [];
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([], vpTokenRequest.requestParams.nonce!)
      }
      await rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      );
    });
    test("Should accept a direct VP Request", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      const vpTokenRequest = await rp.directVpTokenRequestForVerification(
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        authServerUrl + "/direct_post"
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string, secondVc as string],
          vpTokenRequest.requestParams.nonce!
        )
      }
      const response = await rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      );
      expect(response.authzCode).toBeUndefined();
      expect(response.redirectUri).toBeUndefined();
    });
  });
  describe("Error responses", () => {
    test("Should reject an invalid VP if the definition ID of the submission is invalid", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.definition_id = "OtherId";
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string, secondVc as string],
          vpTokenRequest.requestParams.nonce!
        )
      }
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
    });
    test("Should reject a VP if definition has no descriptors and submission does", async () => {
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors = [];
      const presentationSubmission = getPresentationSubmission();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string, secondVc as string],
          vpTokenRequest.requestParams.nonce!
        )
      }
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
    });
    test("Should reject an invalid VP if the input descriptor ID is invalid", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.descriptor_map[1].id = "other-id";
      presentationSubmission.definition_id = "OtherId";
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string, secondVc as string],
          vpTokenRequest.requestParams.nonce!
        )
      }
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
    });
    test("Should reject an invalid VP if not all descriptor are provided", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      presentationSubmission.descriptor_map.pop();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string,
          secondVc as string],
          vpTokenRequest.requestParams.nonce!)
      }
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
    });
    test("Should reject an invalid VP if not all credentials are provided", async () => {
      const presentationDefinition = getPresentationDefinition();
      const presentationSubmission = getPresentationSubmission();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken([firstVc as string], vpTokenRequest.requestParams.nonce!)
      }
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
    });
    test("Should reject an invalid VP if claim schema is not satisfied", async () => {
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors[1].constraints.fields![1].filter = {
        type: 'string',
      } as any;
      const presentationSubmission = getPresentationSubmission();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string, secondVc as string],
          vpTokenRequest.requestParams.nonce!
        )
      };
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
    });
    test("Should reject an invalid VP if nonce is invalid", async () => {
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors[1].constraints.fields![1].filter = {
        type: 'string',
      } as any;
      const presentationSubmission = getPresentationSubmission();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string,
          secondVc as string],
          vpTokenRequest.requestParams.nonce!)
      };
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
    });
    test("Should reject an invalid VP verification callback fail", async () => {
      const rp = new OpenIdRPStepBuilder(
        generateDefaultAuthorisationServerMetadata("https://issuer")
      )
        .withVpCredentialExternalVerification(async (vc, dm, key) => {
          return Result.Err(new Error("Invalid"));
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
        .withTokenSignCallback(signCallback)
        .withStateManager(new MemoryStateManager())
        .build();
      const presentationDefinition = getPresentationDefinition();
      presentationDefinition.input_descriptors[1].constraints.fields![1].filter = {
        type: 'string',
      } as any;
      const presentationSubmission = getPresentationSubmission();
      const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
        "code",
        holderDid,
        "openid:",
        {},
        await generateChallenge(codeVerifier),
        "ES256"
      ).build()
      // Verify AuthzRequest
      let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
        authzRequest,
      );
      // Create ID Token Request
      const vpTokenRequest = await rp.createVpTokenRequest(
        verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
        verifiedAuthzRequest.authzRequest.client_id,
        authServerUrl + "/direct_post",
        {
          type: "Raw",
          presentationDefinition: presentationDefinition
        },
        {
          type: "Verification",
          verifiedBaseAuthzRequest: verifiedAuthzRequest,
        }
      );
      const vpResponse = {
        presentation_submission: presentationSubmission,
        vp_token: await generateVpToken(
          [firstVc as string, secondVc as string],
          vpTokenRequest.requestParams.nonce!
        )
      };
      await expect(rp.verifyVpTokenResponse(
        vpResponse,
        presentationDefinition,
      )).rejects.toThrow();
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

async function generateProof(nonce: string) {
  const header = {
    typ: "openid4vci-proof+jwt",
    alg: "ES256",
    kid: `${holderDid}#${holderKid}`
  };
  const keyLike = await importJWK(holderJWK);
  return await new SignJWT({ nonce })
    .setProtectedHeader(header)
    .setExpirationTime("15m")
    .setIssuer(holderDid)
    .setAudience(authServerUrl)
    .setIssuedAt()
    .sign(keyLike);
}

async function generateVpToken(vc: string[], nonce: string) {
  const vp: W3CVerifiablePresentation = {
    "@context": [CONTEXT_VC_DATA_MODEL_2],
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
  return await new SignJWT({ vp, nonce })
    .setProtectedHeader(header)
    .setExpirationTime("15m")
    .setIssuer(holderDid)
    .setAudience(authServerUrl)
    .setIssuedAt()
    .sign(keyLike);
}

async function generateTokenResponse(vc: string) {
  const rp = new OpenIdRPStepBuilder(
    generateDefaultAuthorisationServerMetadata(authServerUrl),
  )
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
    .withStateManager(memoryManager)
    .build();

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
        [vc]
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
  return await rp.generateAccessToken(
    tokenRequest,
    false,
    // signCallback,
    authServerUrl,
    issuerJWK
  );
}

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