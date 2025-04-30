import { JWK } from 'jose';
import { Resolvable, Resolver } from 'did-resolver';
import { AuthServerMetadata } from '../../common/interfaces/auth_server_metadata.interface.js';
import { AuthzRequestWithJWT } from '../../common/interfaces/authz_request.interface.js';
import { HolderMetadata } from '../../common/interfaces/client_metadata.interface.js';
import { IdTokenRequest } from '../../common/classes/id_token_request.js';
import { IdTokenResponse } from '../../common/interfaces/id_token_response.js';
import { TokenRequest } from '../../common/interfaces/token_request.interface.js';
import { TokenResponse } from '../../common/interfaces/token_response.interface.js';
import * as RpTypes from './types.js';
import { AuthorizationDetails, DIFPresentationDefinition, VpTokenResponse } from '../../common/index.js';
import { VpTokenRequest } from '../../common/classes/vp_token_request.js';
import { CredentialAdditionalVerification } from '../presentations/types.js';
import { Result } from '../../common/classes/result.js';
import { StateManager } from '../state/index.js';
/**
 * Represents an entity acting as a Reliying Party. As such, it has the
 * capability to process authorisation requests and to send others.
 * It can also issue access tokens.
 *
 * The "grant_type" "authorisation_code" and "pre-authorised_code" are supported
 * for authentication. The first one is always active. In order to facilitate the
 * building of the objects from this class, a builder has been developed.
 * @class OpenIDReliyingParty
 */
export declare class OpenIDReliyingParty {
    private defaultHolderMetadata;
    private metadata;
    private didResolver;
    private signCallback;
    private scopeVerificationFlag;
    private subjectComparison;
    private generalConfiguration;
    private issuerStateVerirication?;
    private authzDetailsVerification?;
    private vpCredentialVerificationCallback?;
    private preAuthCallback?;
    private nonceManager;
    /**
     * @param defaultHolderMetadata Default metadata configuration for all Holder Wallets
     * that establish contact. This configuration is overwritten dynamically with the
     * data provided by these actors.
     * @param metadata Authorisation server metadata
     * @param didResolver Object responsible for obtaining the DID Documents
     * of the DIDs that are detected.
     * @param signCallback Callback used to sign any required data.
     * @param scopeVerificationFlag Flag that control if the scope parameter
     * should be checked against the "scopes_supported" params of the Auth server
     * metadata
     * @param stateManager: An implementation of a State Manager that will be used to
     * store and control the lifetime of the nonces
     * @param subjectComparison Function used to compare if two ID, most probably DIDs,
     * are the same
     * @param generalConfiguration Configuration about the different expiration times
     * of the involved tokens
     * @param issuerStateVerirication Optional callback that can be used to check the "issuer state"
     * parameter, but only is provided
     * @param authzDetailsVerification Optional callback that can be used to check
     * the authorization details of a Authz Request, but only if provided
     * @param vpCredentialVerificationCallback Optional callback that is used during
     * VP verification to check the credential data against the use case logic.
     * @param preAuthCallback Optional callback that is used to check the validity
     * of a Pre-Authorization Code
     */
    constructor(defaultHolderMetadata: HolderMetadata, metadata: AuthServerMetadata, didResolver: Resolver, signCallback: RpTypes.TokenSignCallback, scopeVerificationFlag: boolean, stateManager: StateManager, subjectComparison: (firstId: string, secondId: string) => boolean, generalConfiguration: RpTypes.RpConfiguration, issuerStateVerirication?: ((state: string) => Promise<Result<null, Error>>) | undefined, authzDetailsVerification?: ((authDetails: AuthorizationDetails) => Promise<Result<null, Error>>) | undefined, vpCredentialVerificationCallback?: CredentialAdditionalVerification | undefined, preAuthCallback?: undefined | ((clientId: string | undefined, preCode: string, pin?: string) => Promise<Result<string, Error>>));
    /**
     * Adds support for a new DID method by extending the internal resolver.
     *
     * @param methodName - The DID method name (e.g., 'key', 'web').
     * @param resolver - A Resolvable that can resolve DIDs for the given method.
     */
    addDidMethod(methodName: string, resolver: Resolvable): void;
    /**
     * Creates a new ID Token Request object to initiate an OpenID authorization flow.
     *
     * @param clientAuthorizationEndpoint - The client's authorization endpoint URL.
     * @param audience - Audience value to be used as the JWT 'aud' claim.
     * @param redirectUri - Redirect URI where the response should be sent.
     * @param requestPurpose - Purpose of the request (e.g., issuance or verification).
     * @param additionalParameters - Optional parameters for token customization.
     * @returns An instance of {@link IdTokenRequest}.
     */
    createIdTokenRequest(clientAuthorizationEndpoint: string, audience: string, redirectUri: string, requestPurpose: RpTypes.RequestPurpose, additionalParameters?: RpTypes.CreateTokenRequestOptionalParams): Promise<IdTokenRequest>;
    /**
       * Creates a direct VP Token Request for verification purposes, without a prior base authz.
       *
       * @param presentationDefinition - Presentation definition or URI.
       * @param redirectUri - Redirect URI where the response should be sent.
       * @param additionalParameters - Optional parameters to customize the VP request.
       * @returns An instance of {@link VpTokenRequest}.
       */
    directVpTokenRequestForVerification(presentationDefinition: RpTypes.PresentationDefinitionLocation, redirectUri: string, additionalParameters?: RpTypes.CreateTokenRequestOptionalParams): Promise<VpTokenRequest>;
    /**
       * Creates an ID Token request for verification scenarios using the 'direct_post' response mode,
       * without requiring a prior authorization request.
       *
       * @param redirectUri - Redirect URI where the ID Token response should be delivered.
       * @param additionalParameters - Optional parameters to customize the ID Token payload.
       * @returns A signed ID Token request
       */
    directIdTokenRequestForVerification(redirectUri: string, additionalParameters?: RpTypes.CreateTokenRequestOptionalParams): Promise<IdTokenRequest>;
    /**
     * Creates a new VP Token request based on a base authorization request and presentation definition.
     *
     * This method is used in issuance or verification flows where the user has already gone through a
     * base authorization phase and a `vp_token` is expected as the response.
     *
     * @param clientAuthorizationEndpoint - The endpoint to which the client will send the authorization request.
     * @param audience - The audience for the VP Token, typically the verifier's identifier.
     * @param redirectUri - The URI where the client expects to receive the response.
     * @param presentationDefinition - A definition or reference describing what credentials are expected.
     * @param requestPurpose - The purpose of the request, including the prior verified authz request.
     * @param additionalParameters - Optional customization parameters (expiration time, scope, etc).
     * @returns A {@link VpTokenRequest} containing all request parameters and a signed token.
     */
    createVpTokenRequest(clientAuthorizationEndpoint: string, audience: string, redirectUri: string, presentationDefinition: RpTypes.PresentationDefinitionLocation, requestPurpose: RpTypes.RequestPurpose, additionalParameters?: RpTypes.CreateTokenRequestOptionalParams): Promise<VpTokenRequest>;
    private createNonceForPostBaseAuthz;
    /**
     * Verifies an incoming Authorization Request, extracting and validating parameters from a JWT or plain request.
     *
     * If a signed request object is present, this method validates the JWT signature, ensures all mandatory fields
     * are available (like client_metadata and jwks_uri), and checks supported algorithms against metadata policies.
     *
     * It also validates `authorization_details` if configured, ensures the `issuer_state` is acceptable,
     * and resolves client metadata.
     *
     * @param request - The Authorization Request received from the Holder Wallet or client.
     * @returns A verified request object including client metadata and optional service wallet JWK.
     * @throws {InvalidRequest} If the request is malformed or uses unsupported features.
     */
    verifyBaseAuthzRequest(request: AuthzRequestWithJWT): Promise<RpTypes.VerifiedBaseAuthzRequest>;
    private createNonceForPostAuthz;
    private checkNonceStateForPostBaseAuthz;
    /**
     * Verifies an ID Token response received from a client.
     *
     * This method checks the token's structure, signature (if enabled), and expiration. It also validates
     * that the `nonce` and `state` values match those previously issued during the authorization request.
     * It ensures the DID associated with the token can be resolved, and the public key referenced by the `kid`
     * is present and valid.
     *
     * @param idTokenResponse - The response object containing the ID Token to be verified.
     * @param checkTokenSignature - Whether the signature of the token should be verified. Enabled by default.
     * @returns A verified response with the subject, DID Document, redirect URI and any associated authorization code.
     * @throws {InvalidRequest | AccessDenied} If validation fails due to expiration, audience mismatch,
     * incorrect issuer, or inability to resolve the DID or verify the token.
     */
    verifyIdTokenResponse(idTokenResponse: IdTokenResponse, checkTokenSignature?: boolean): Promise<RpTypes.VerifiedIdTokenResponse>;
    /**
     * Verifies a VP Token Response from the client.
     *
     * This method verifies the verifiable presentation (VP) submitted in the response,
     * ensuring it meets the expected presentation definition and signature requirements.
     * It also verifies the nonce state and returns relevant extracted data, including
     * the internal VC data and an optional authorization code.
     *
     * @param vpTokenResponse - The response containing the VP Token and presentation submission.
     * @param presentationDefinition - The presentation definition that the VP must fulfill.
     * @param vcSignatureVerification - Whether to validate the VC signatures inside the VP. Defaults to true.
     * @returns A verified response containing the VP Token, internal VC data, and optional authz code.
     * @throws {InternalNonceError | OpenIdError} If nonce verification, signature checks, or VC validation fails.
     */
    verifyVpTokenResponse(vpTokenResponse: VpTokenResponse, presentationDefinition: DIFPresentationDefinition, vcSignatureVerification?: boolean): Promise<RpTypes.VerifiedVpTokenResponse>;
    private processNonceForPostAuthz;
    private generateCNonce;
    /**
     * Generates an access token based on the token request and previously validated authorization.
     *
     * Supports `authorization_code` and `pre-authorized_code` grant types. Depending on the grant type,
     * it verifies the authorization code or invokes a pre-auth callback. Also optionally generates an ID Token
     * if requested, and includes any additional claims (e.g., `pin`, `vc_types`, or `verification_scope`).
     *
     * @param tokenRequest - The request object containing grant type and related credentials.
     * @param generateIdToken - Whether to include an ID Token in the response.
     * @param audience - Audience value for the access token.
     * @param authServerPublicKeyJwk - Public JWK used to verify the authorization code.
     * @returns A {@link TokenResponse} including access token, optional ID token, and c_nonce values.
     * @throws {UnsupportedGrantType | InvalidGrant | InvalidRequest | InsufficienteParamaters} If request validation fails.
     */
    generateAccessToken(tokenRequest: TokenRequest, generateIdToken: boolean, audience: string, authServerPublicKeyJwk: JWK): Promise<TokenResponse>;
    private validateClientMetadata;
    private resolveClientMetadata;
}
export * from './types.js';
export * from './builder.js';
