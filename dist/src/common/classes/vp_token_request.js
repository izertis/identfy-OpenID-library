/**
 * Define an authorisation request that expects an VP token as "response_type"
 */
export class VpTokenRequest {
    requestParams;
    request;
    clientAuthorizationEndpoint;
    /**
     * Constructor of the class
     * @param requestParams VP Token request parameters
     * @param request The request as a JWT
     * @param clientAuthorizationEndpoint
     */
    constructor(requestParams, request, clientAuthorizationEndpoint) {
        this.requestParams = requestParams;
        this.request = request;
        this.clientAuthorizationEndpoint = clientAuthorizationEndpoint;
    }
    /**
     * Encode the request in URL format
     * @returns The request in URL format
     */
    toUri() {
        const data = { ...this.requestParams };
        delete data.presentation_definition;
        delete data.presentation_definition_uri;
        return `${this.clientAuthorizationEndpoint}?${new URLSearchParams(Object.entries({
            ...data,
            request: this.request,
        })).toString()}`;
    }
}
//# sourceMappingURL=vp_token_request.js.map