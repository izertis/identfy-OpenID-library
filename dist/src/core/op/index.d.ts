import { AuthorizationDetails } from "../../common/interfaces/authz_details.interface.js";
import { AuthzRequest, AuthzRequestLocation } from "../../common/interfaces/authz_request.interface.js";
import { HolderMetadata, ServiceMetadata } from "../../common/interfaces/client_metadata.interface.js";
import { AuthzResponseType } from "../../common/types/index.js";
/**
 * Extended authorisation request
 */
interface AuthzRequestMethodData {
    /**
     * The petition in JWT format.
     */
    jwt?: string;
    /**
     * The URL to send the request to
     */
    url: string;
    /**
     * The state associated with the request
     */
    state: string;
    /**
     * The "code_verifier" that resolves the challenge included
     * in the request
     */
    code_verifier?: string;
}
/**
 * Define an entity acting as OpenIDProvider. As such, it can generate
 * authorisation requests
 */
export declare class OpenIDProvider {
    private redirectUri;
    private requestCallback;
    private metadata;
    private clientId;
    /**
     * Constructor of the OpenIDProvider class
     * @param redirectUri URI at which responses to authorisation requests
     *  are expected to be received
     * @param requestCallback Callback that allow to sign the request objects
     * @param metadata The authorisation metadata of the OP
     * @param clientId The identifier of the OP
     */
    constructor(redirectUri: string, requestCallback: AuthzSignCallback, metadata: ServiceMetadata | HolderMetadata, clientId: string);
    /**
     * Allows to generate an autorisation request
     * @param url The URL to send the request to
     * @param requestLocation Allows to indicate where the request parameters
     * should be included.
     * @param response_type The response type expected
     * @param authzDetails The autorisation details to include in the request
     * @param scope The scope to include in the request
     * @param audience The "aud" parameter to include in the request if a JWT is generated.
     * @param pkceChallenge The challenge to include in the request.
     * @returns The authorisation request to sent in URL format with additional information.
     */
    createBaseAuthzRequest(url: string, requestLocation: AuthzRequestLocation, response_type: AuthzResponseType, // Most probably could be set to "code"
    authzDetails: AuthorizationDetails, scope: string, audience: string, pkceChallenge?: {
        code_challenge: string;
        code_challenge_method: string;
    }): Promise<AuthzRequestMethodData>;
    createIdTokenReponse(): void;
    createVpTokenResponse(): void;
    verifyIdTokenRequest(): void;
    verifyVpTokenResponse(): void;
    verifyAuthzResponse(): void;
}
/**
 * Function type that allows to sign an AuthzRequest
 * @param data The request to sign
 * @param target The audience of the request
 * @returns The signed request in string format
 */
export type AuthzSignCallback = (data: AuthzRequest, target: string) => Promise<string>;
export {};
