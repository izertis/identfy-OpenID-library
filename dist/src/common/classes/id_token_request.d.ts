import { AuthzResponseMode } from "../formats/index.js";
/**
 * Define an authorisation request that expects an ID token as "response_type"
 */
export declare class IdTokenRequest {
    requestParams: IdTokenRequestParams;
    request: string;
    private clientAuthorizationEndpoint;
    /**
     * Constructor of the class
     * @param requestParams ID Token request parameters
     * @param request The request as a JWT
     * @param clientAuthorizationEndpoint
     */
    constructor(requestParams: IdTokenRequestParams, request: string, clientAuthorizationEndpoint: string);
    /**
     * Encode the request in URL format
     * @returns The request in URL format
     */
    toUri(): string;
}
/**
 * Parameters of a ID Token Request
 */
export interface IdTokenRequestParams {
    response_type: "id_token";
    client_id: string;
    scope: string;
    redirect_uri: string;
    response_mode?: AuthzResponseMode;
    state?: string;
    nonce?: string;
}
