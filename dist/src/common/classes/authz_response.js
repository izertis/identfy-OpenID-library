/**
 * Represents an authorization response for the "code" response type
 */
export class AuthorizationResponse {
    /**
     * Contructor of this class
     * @param uri The URI to which this response should be delivered
     * @param code The authorization code to include
     * @param state The state sent by the client in the original Authz request
     */
    constructor(uri, code, state) {
        this.uri = uri;
        this.code = code;
        this.state = state;
    }
    /**
     * Allows to express the response in URL format
     * @returns String with response in URL format
     */
    toUri() {
        const params = { code: this.code };
        if (this.state) {
            params.state = this.state;
        }
        return `${this.uri}?${new URLSearchParams(Object.entries(params)).toString()}`;
    }
}
