import { InvalidDataProvided } from "../../classes/index.js";
import { DEFAULT_SCOPE } from "../../constants/index.js";
/**
 * Builder class for AuthzRequest
 */
export class AuthzRequestBuilder {
    /**
     * Constructor for AuthzRequestBuilder
     * @param response_type The "reponse_type" attribute of an authorization request
     * @param client_id  The client identifier
     * @param redirect_uri  The "redirect_uri" attribute of an authorization request
     * @param imposeOpenIdScope Flag that manages whether "scope" should
     * be checked for the string "openid".
     */
    constructor(response_type, client_id, redirect_uri, imposeOpenIdScope = true) {
        this.response_type = response_type;
        this.client_id = client_id;
        this.redirect_uri = redirect_uri;
        this.imposeOpenIdScope = imposeOpenIdScope;
        this.scope = DEFAULT_SCOPE;
    }
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
    static holderAuthzRequestBuilder(response_type, client_id, redirect_uri, metadata, code_challenge, code_challenge_method, issuer_state) {
        const builder = new AuthzRequestBuilder(response_type, client_id, redirect_uri)
            .withMetadata(metadata)
            .withCodeChallenge(code_challenge, code_challenge_method);
        if (issuer_state) {
            builder.withIssuerState(issuer_state);
        }
        return builder;
    }
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
    static serviceAuthzRequestBuilder(response_type, client_id, redirect_uri, metadata, issuer_state) {
        const builder = new AuthzRequestBuilder(response_type, client_id, redirect_uri)
            .withMetadata(metadata);
        if (issuer_state) {
            builder.withIssuerState(issuer_state);
        }
        return builder;
    }
    /**
     * Set the attribute "client_metadata" of an autorization request
     * @param metadata The metadata to include
     * @returns This object
     */
    withMetadata(metadata) {
        this.client_metadata = metadata;
        return this;
    }
    /**
     * Set the attribute "code_challenge" of an autorization request
     * @param code_challenge The challenge to include
     * @param method The method that have to be used to verify the challenge
     * @returns This object
     */
    withCodeChallenge(code_challenge, method) {
        this.code_challenge = code_challenge;
        this.code_challenge_method = method;
        return this;
    }
    /**
     * Set the attribute "scope" of an autorization request
     * @param scope The scope to include
     * @returns This object
     */
    withScope(scope) {
        if (this.imposeOpenIdScope && !scope.includes(DEFAULT_SCOPE)) {
            throw new InvalidDataProvided(`Scope must contain ${DEFAULT_SCOPE}`);
        }
        this.scope = scope;
        return this;
    }
    /**
     * Set the attribute "issuer_state" of an autorization request
     * @param issuerState The state to include
     * @returns This object
     */
    withIssuerState(issuerState) {
        this.issuer_state = issuerState;
        return this;
    }
    /**
     * Set the attribute "state" of an autorization request
     * @param state The state to include
     * @returns This object
     */
    withState(state) {
        this.state = state;
        return this;
    }
    /**
     * Set the attribute "nonce" of an autorization request
     * @param nonce The nonce to include
     * @returns This object
     */
    withNonce(nonce) {
        this.nonce = nonce;
        return this;
    }
    /**
     * Add authorization details to an autorization request
     * @param authorizationDetails The details to include
     * @returns This object
     */
    addAuthzDetails(authorizationDetails) {
        if (!this.authorization_details) {
            this.authorization_details = [];
        }
        this.authorization_details.push(authorizationDetails);
        return this;
    }
    /**
     * Generate AuthzRequest from the data contained in the builder
     * @returns AuthzRequest instance
     */
    build() {
        return {
            response_type: this.response_type,
            client_id: this.client_id,
            redirect_uri: this.redirect_uri,
            scope: this.scope,
            issuer_state: this.issuer_state,
            state: this.state,
            authorization_details: this.authorization_details,
            nonce: this.nonce,
            code_challenge: this.code_challenge,
            code_challenge_method: this.code_challenge_method,
            client_metadata: this.client_metadata
        };
    }
}
