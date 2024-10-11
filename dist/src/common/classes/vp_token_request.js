/**
 * Define an authorisation request that expects an VP token as "response_type"
 */
export class VpTokenRequest {
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
        const data = Object.assign({}, this.requestParams);
        delete data.presentation_definition;
        delete data.presentation_definition_uri;
        return `${this.clientAuthorizationEndpoint}?${new URLSearchParams(Object.entries(Object.assign(Object.assign({}, data), { request: this.request }))).toString()}`;
    }
}
