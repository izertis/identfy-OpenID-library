import { JWK } from "jose";
import { DIDDocument, Resolvable, Resolver } from "did-resolver";
import { AuthServerMetadata } from "../../common/interfaces/auth_server_metadata.interface.js";
import { AuthzRequest, AuthzRequestWithJWT } from "../../common/interfaces/authz_request.interface.js";
import { IdTokenRequest } from "../../common/classes/id_token_request.js";
import { IdTokenResponse } from "../../common/interfaces/id_token_response.js";
import { AuthorizationResponse } from "../../common/classes/authz_response.js";
import { TokenRequest } from "../../common/interfaces/token_request.interface.js";
import { TokenResponse } from "../../common/interfaces/token_response.interface.js";
import * as RpTypes from "./types.js";
import { DIFPresentationDefinition, VpTokenResponse } from "../../common/index.js";
import { VpTokenRequest } from "../../common/classes/vp_token_request.js";
import { CredentialAdditionalVerification, NonceVerification, VpExtractedData } from "../presentations/types.js";
export interface VerifiedBaseAuthzRequest {
    /**
     * Client metadata related to supported formats and algorithms that are checked against the PR.
     */
    validatedClientMetadata: RpTypes.ValidatedClientMetadata;
    /**
     * Verified authz request
     */
    authzRequest: AuthzRequest;
    /**
     * JWK used by the service Wallet
     */
    serviceWalletJWK?: JWK;
}
interface VerifiedIdTokenResponse {
    didDocument: DIDDocument;
    token: string;
}
interface VerifiedVpTokenResponse {
    token: string;
    vpInternalData: VpExtractedData;
}
/**
 * Represents an entity acting as a Reliying Party. As such, it has the
 * capability to process authorisation requests and to send others.
 * It can also issue access tokens.
 *
 * The "grant_type" "authorisation_code" and "pre-authorised_code" are supported
 * for authentication.
 *
 */
export declare class OpenIDReliyingParty {
    private defaultMetadataCallback;
    private metadata;
    private didResolver;
    private vpCredentialVerificationCallback;
    /**
     * @param defaultMetadataCallback Callback to get the default value to
     * consider for client metadata.
     * @param metadata Authorisation server metadata
     * @param didResolver Object responsible for obtaining the DID Documents
     * of the DIDs that are detected.
     * @param vpCredentialVerificationCallback Optional callback needed to verify for
     * CredentialStatus and Verification
     */
    constructor(defaultMetadataCallback: RpTypes.GetClientDefaultMetada, metadata: AuthServerMetadata, didResolver: Resolver, vpCredentialVerificationCallback: CredentialAdditionalVerification);
    /**
     * Allows to add support for a new DID Method
     * @param methodName DID Method name
     * @param resolver Object responsible for obtaining the DID Documents
     * related to the DID specified
     */
    addDidMethod(methodName: string, resolver: Resolvable): void;
    /**
     * Allows to create a new Authorisation request in which an ID Token
     * is requested
     * @param clientAuthorizationEndpoint Endpoint of the authorisation
     * server of the client
     * @param audience "aud" parameter for the generated JWT.
     * @param redirectUri URI to which the client should deliver the
     * authorisation response to
     * @param jwtSignCallback Callback to generate the signed ID Token
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the ID Token.
     * @returns The ID Token Request
     */
    createIdTokenRequest(clientAuthorizationEndpoint: string, audience: string, redirectUri: string, jwtSignCallback: RpTypes.TokenSignCallback, additionalParameters?: RpTypes.CreateIdTokenRequestOptionalParams): Promise<IdTokenRequest>;
    /**
     * Allows to create a new Authorisation request in which an VP Token
     * is requested
     * @param clientAuthorizationEndpoint Endpoint of the authorisation
     * server of the client
     * @param audience "aud" parameter for the generated JWT.
     * @param redirectUri URI to which the client should deliver the
     * authorisation response to
     * @param jwtSignCallback Callback to generate the signed VP Token
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the VP Token.
     * @returns The VP Token Request
     */
    createVpTokenRequest(clientAuthorizationEndpoint: string, audience: string, redirectUri: string, jwtSignCallback: RpTypes.TokenSignCallback, additionalParameters?: RpTypes.CreateVpTokenRequestOptionalParams): Promise<VpTokenRequest>;
    /**
     * Allows to verify an authorisation request sent by a client
     * @param request The request sent by the client
     * @param additionalParameters Optional parameters allowing
     * validations to be applied to the "scope", "authorisation_details"
     * and "issuer_state" parameters of the authorisation request
     * @returns Verified Authz Reques with some of the client metadata extracted
     */
    verifyBaseAuthzRequest(request: AuthzRequestWithJWT, additionalParameters?: RpTypes.VerifyBaseAuthzRequestOptionalParams): Promise<VerifiedBaseAuthzRequest>;
    /**
     * Allows to verify an ID Token Response sent by a client
     * @param idTokenResponse The authorisation response to verify
     * @param verifyCallback A callback that allows to verify the contents of the
     * header and payload of the received ID Token, but no the signature
     * @returns The verified ID Token Response with the DID Document of the
     * associated token issuer.
     * @throws If data provided is incorrect
     */
    verifyIdTokenResponse(idTokenResponse: IdTokenResponse, verifyCallback: RpTypes.IdTokenVerifyCallback): Promise<VerifiedIdTokenResponse>;
    /**
     * Allows to verify an VP Token Response sent by a client
     * @param vpTokenResponse The authorisation response to verify
     * @param presentationDefinition The presentation definition to use to
     * verify the VP
     * @param nonceVerificationCallback A callback used to verify the nonce of a JWT_VP
     * @param vcSignatureVerification A callback that can be used to perform additional
     * verification of any of the VC extracted from the VP. This can be used to check
     * the status of any VC and its terms of use.
     * @returns The verified VP Token Response with holder DID and the data
     * extracted from the VCs of the VP
     * @throws If data provided is incorrect
     */
    verifyVpTokenResponse(vpTokenResponse: VpTokenResponse, presentationDefinition: DIFPresentationDefinition, nonceVerificationCallback: NonceVerification, vcSignatureVerification?: boolean): Promise<VerifiedVpTokenResponse>;
    /**
     * Generates an authorisation response for a request with response type
     * "code".
     * @param redirect_uri The URI to send the response to
     * @param code The authorisation code to be sent
     * @param state The state to associate with the response. It must be
     * the same as the one sent by the client in the corresponding
     * authorisation request if this parameter was present.
     * @returns Authorization response
     */
    createAuthzResponse(redirect_uri: string, code: string, state?: string): AuthorizationResponse;
    /**
     * Allows to generate a token response from a token request
     * @param tokenRequest The token request sent by the client
     * @param generateIdToken Flag indicating whether, together with
     * the access token, an ID Token should be generated.
     * @param tokenSignCallback Callback that manages the signature of the token.
     * @param audience JWT "aud" to include in the generated access token
     * @param optionalParamaters Optional arguments to specify the nonce to be used, the time
     * validity of the nonce and callbacks to check the authorisation
     * and pre-authorisation codes sent. They also allow to specify how to
     * validate the code_challenge sent by the user in an authorisation request
     * @returns Token response with the generated access token
     * @throws If data provided is incorrect
     */
    generateAccessToken(tokenRequest: TokenRequest, generateIdToken: boolean, tokenSignCallback: RpTypes.TokenSignCallback, audience: string, optionalParamaters?: RpTypes.GenerateAccessTokenOptionalParameters): Promise<TokenResponse>;
    private validateClientMetadata;
    private resolveClientMetadata;
}
export * from "./types.js";
