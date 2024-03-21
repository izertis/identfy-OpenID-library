import { JWA_ALGS } from "../../common/constants/index.js";
import { AuthzResponseMode } from "../../common/formats/index.js";
import {
  AuthorizationDetails
} from "../../common/interfaces/authz_details.interface.js";
import {
  HolderMetadata
} from "../../common/interfaces/client_metadata.interface.js";
import {
  VerificationResult,
  VpFormatsSupported
} from "../../common/types/index.js";
import { DIDDocument } from "did-resolver";
import { JwtHeader, JwtPayload } from "jsonwebtoken";

/**
 * Defines a function type that allows signing a JWT Payload
 * @param payload JWT payload to sign
 * @param supportedSignAlg List of supported signature algorithms,
 *  of which one should be used.
 * @returns The signed object in a string format.
 */
export type TokenSignCallback = (
  payload: JwtPayload,
  supportedSignAlg?: JWA_ALGS[]
) => Promise<string>;

/**
 * Defines a function type that allows the verification of an ID Token
 * @param header JWT Header of the ID Token
 * @param payload JWT payload if the ID Token
 * @param didDocument DID Document of the entity the token relates to
 * @returns Indication of whether the verification was successful 
 * accompanied by an optional error message
 */
export type IdTokenVerifyCallback = (
  header: JwtHeader,
  payload: JwtPayload,
  didDocument: DIDDocument
) => Promise<VerificationResult>;

/**
 * Defines a function type that allows to get the default metadata of clients
 * @returns The metadata of the client
 */
export type GetClientDefaultMetada = () => Promise<HolderMetadata>;

/**
 * Defines an object type which allows to specify the optional parameters of 
 * VerifyBaseAuthzRequest OpenIDReliyingParyy method
 */
export type VerifyBaseAuthzRequestOptionalParams = {
  /**
   * Function for verifying the authorisation details of an authorisation request
   * @param authDetails Details to verify
   * @returns Indication of whether the verification was successful 
   * accompanied by an optional error message
   */
  authzDetailsVerifyCallback?: (authDetails: AuthorizationDetails) => Promise<VerificationResult>;
  /**
   * Function for verifying the scope of an authorisation request
   * @param scope The scope of the authz request
   * @returns Indication of whether the verification was successful 
   * accompanied by an optional error message
   */
  scopeVerifyCallback?: (scope: string) => Promise<VerificationResult>;
  /**
   * Function for verifying the "issuer_state" parameter of an authorisation request
   * @param state The state of the issuer sent in a Credential Offer
   * @returns Indication of whether the verification was successful 
   * accompanied by an optional error message
   */
  issuerStateVerifyCallback?: (state: string) => Promise<VerificationResult>;
};

/**
 * Defines an object type that allows to specify the optional parameters of
 * "generateAccessToken" OpenIDReliyingParty method
 */
export interface GenerateAccessTokenOptionalParameters {
  /**
   * Allows to verify the authorisation code sent with the token request
   * @param clientId The identifier of the client
   * @param code The code itself
   * @returns Indication of whether the verification was successful 
   * accompanied by an optional error message
   */
  authorizeCodeCallback?: (
    clientId: string,
    code: string
  ) => Promise<VerificationResult>;
  /**
   * Allows to verify the pre-authorised cose sent with the token request
   * @param clientId The identifier of the client
   * @param preCode The code itself
   * @param pin The PIN sent by the client
   * @returns Indication of whether the verification was successful 
   * accompanied by an optional error message
   */
  preAuthorizeCodeCallback?: (
    clientId: string | undefined,
    preCode: string,
    pin?: string
  ) => Promise<{ client_id?: string, error?: string }>;
  /**
   * Allows to verify the "code_challenge" parameter sent by an user in 
   * a previous authorisation request
   * @param clientId The identifier of the client
   * @param codeVerifier The code_verifier of the previously received challenge
   * @returns Indication of whether the verification was successful 
   * accompanied by an optional error message
   */
  codeVerifierCallback?: (
    clientId: string,
    codeVerifier?: string
  ) => Promise<VerificationResult>,
  cNonceToEmploy?: string;
  cNonceExp?: number;
  accessTokenExp?: number;
}

/**
 * Defines an object type that allows to specify the optional parameters of
 * "createIdTokenRequest" OpenIDReliyingParty method
 */
export type CreateIdTokenRequestOptionalParams = {
  /**
   * Response mode to specify in the ID Token
   * @defaultValue "direct_post" 
   */
  responseMode?: AuthzResponseMode;
  /**
   * Additiona payload to include in the JWT 
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

/**
 * Client metadata that has been processed to indicate which formats, signature 
 * algorithms and response types are supported.
 */
export interface ValidatedClientMetadata {
  /**
   * Response types supported by the client
   */
  responseTypesSupported: string[];
  /**
   * Signature algorithms supported by both the client and an RP
   */
  idTokenAlg: JWA_ALGS[];
  /**
   * VP formats supported both by the client and by an RP
   */
  vpFormats: VpFormatsSupported;
  /**
   * Authorization endpoint of the client
   */
  authorizationEndpoint: string;
};
