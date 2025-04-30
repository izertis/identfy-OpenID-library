import { AuthorizationDetails } from '../../interfaces/authz_details.interface.js';
import { AuthzRequest } from '../../interfaces/authz_request.interface.js';
import { HolderMetadata, ServiceMetadata } from '../../interfaces/client_metadata.interface.js';
import { AuthzResponseType } from '../../types/index.js';
/**
 * Builder class for AuthzRequest
 */
export declare class AuthzRequestBuilder {
    private response_type;
    private client_id;
    private redirect_uri;
    private imposeOpenIdScope;
    private scope;
    private issuer_state?;
    private state?;
    private authorization_details?;
    private nonce?;
    private code_challenge?;
    private code_challenge_method?;
    private client_metadata?;
    /**
     * Constructor for AuthzRequestBuilder
     * @param response_type The "reponse_type" attribute of an authorization request
     * @param client_id  The client identifier
     * @param redirect_uri  The "redirect_uri" attribute of an authorization request
     * @param imposeOpenIdScope Flag that manages whether "scope" should
     * be checked for the string "openid".
     */
    constructor(response_type: AuthzResponseType, client_id: string, redirect_uri: string, imposeOpenIdScope?: boolean);
    /**
     * Generates a build with the required data for a AuthzRequest sent
     * by a Holder Wallet
     * @param response_type The "reponse_type" attribute of an authorization request
     * @param client_id The client identifier
     * @param redirect_uri The "redirect_uri" attribute of an authorization request
     * @param metadata The metadata of the Holder
     * @param code_challenge The "code_challenge" attribute of authorization request
     * @param code_challenge_method The "code_challenge_method" attribute of
     * authorization request
     * @param issuer_state The "issuer_state" attribute of authorization request
     * @returns Instance of AuthzRequestBuilder
     */
    static holderAuthzRequestBuilder(response_type: AuthzResponseType, client_id: string, redirect_uri: string, metadata: HolderMetadata, code_challenge: string, code_challenge_method: string, // TODO: Define new type
    issuer_state?: string): AuthzRequestBuilder;
    /**
     * Generates a build with the required data for a AuthzRequest sent
     * by a Service Wallet
     * @param response_type The "reponse_type" attribute of an authorization request
     * @param client_id The client identifier
     * @param redirect_uri The "redirect_uri" attribute of an authorization request
     * @param metadata The metadata of the Holder
     * @param issuer_state The "issuer_state" attribute of authorization request
     * @returns Instance of AuthzRequestBuilder
     */
    static serviceAuthzRequestBuilder(response_type: AuthzResponseType, client_id: string, redirect_uri: string, metadata: ServiceMetadata, issuer_state?: string): AuthzRequestBuilder;
    /**
     * Set the attribute "client_metadata" of an autorization request
     * @param metadata The metadata to include
     * @returns This object
     */
    withMetadata(metadata: HolderMetadata | ServiceMetadata): AuthzRequestBuilder;
    /**
     * Set the attribute "code_challenge" of an autorization request
     * @param code_challenge The challenge to include
     * @param method The method that have to be used to verify the challenge
     * @returns This object
     */
    withCodeChallenge(code_challenge: string, method: string): AuthzRequestBuilder;
    /**
     * Set the attribute "scope" of an autorization request
     * @param scope The scope to include
     * @returns This object
     */
    withScope(scope: string): AuthzRequestBuilder;
    /**
     * Set the attribute "issuer_state" of an autorization request
     * @param issuerState The state to include
     * @returns This object
     */
    withIssuerState(issuerState: string): AuthzRequestBuilder;
    /**
     * Set the attribute "state" of an autorization request
     * @param state The state to include
     * @returns This object
     */
    withState(state: string): AuthzRequestBuilder;
    /**
     * Set the attribute "nonce" of an autorization request
     * @param nonce The nonce to include
     * @returns This object
     */
    withNonce(nonce: string): AuthzRequestBuilder;
    /**
     * Add authorization details to an autorization request
     * @param authorizationDetails The details to include
     * @returns This object
     */
    addAuthzDetails(authorizationDetails: AuthorizationDetails): AuthzRequestBuilder;
    /**
     * Generate AuthzRequest from the data contained in the builder
     * @returns AuthzRequest instance
     */
    build(): AuthzRequest;
}
