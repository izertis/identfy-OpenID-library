/**
 * Represents an authorization response for the "code" response type
 */
export declare class AuthorizationResponse {
    uri: string;
    code: string;
    state?: string | undefined;
    /**
     * Contructor of this class
     * @param uri The URI to which this response should be delivered
     * @param code The authorization code to include
     * @param state The state sent by the client in the original Authz request
     */
    constructor(uri: string, code: string, state?: string | undefined);
    /**
     * Allows to express the response in URL format
     * @returns String with response in URL format
     */
    toUri(): string;
}
