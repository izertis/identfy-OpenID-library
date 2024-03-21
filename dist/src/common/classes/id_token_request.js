/**
 * Define an authorisation request that expects an ID token as "response_type"
 */
export class IdTokenRequest {
    /**
     * Constructor of the class
     * @param requestParams ID Token request parameters
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
        return `${this.clientAuthorizationEndpoint}?${new URLSearchParams(Object.entries(Object.assign(Object.assign({}, this.requestParams), { request: this.request }))).toString()}`;
    }
}
