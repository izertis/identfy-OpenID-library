import { AuthzResponseMode } from "../formats/index.js";
import { DIFPresentationDefinition } from "../interfaces/presentation_definition.interface.js";
/**
 * Define an authorisation request that expects an VP token as "response_type"
 */
export declare class VpTokenRequest {
    requestParams: VpTokenRequestParams;
    request: string;
    private clientAuthorizationEndpoint;
    /**
     * Constructor of the class
     * @param requestParams VP Token request parameters
     * @param request The request as a JWT
     * @param clientAuthorizationEndpoint
     */
    constructor(requestParams: VpTokenRequestParams, request: string, clientAuthorizationEndpoint: string);
    /**
     * Encode the request in URL format
     * @returns The request in URL format
     */
    toUri(): string;
}
/**
 * Parameters of a VP Token Request
 */
export interface VpTokenRequestParams {
    response_type: "vp_token";
    presentation_definition?: DIFPresentationDefinition;
    presentation_definition_uri?: string;
    client_id: string;
    scope: string;
    redirect_uri: string;
    response_mode?: AuthzResponseMode;
    state?: string;
    nonce?: string;
}
