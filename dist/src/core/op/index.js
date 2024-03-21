var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { v4 as uuidv4 } from 'uuid';
import querystring from "querystring";
import { AuthzRequestBuilder } from "../../common/builders/authz/authz_request.builder.js";
import { AuthzRequestLocation } from "../../common/interfaces/authz_request.interface.js";
import { generateChallenge } from "../../common/utils/pkce.utils.js";
import { DEFAULT_PKCE_LENGTH, generateRandomString } from '../../common/index.js';
/**
 * Define an entity acting as OpenIDProvider. As such, it can generate
 * authorisation requests
 */
export class OpenIDProvider {
    /**
     * Constructor of the OpenIDProvider class
     * @param redirectUri URI at which responses to authorisation requests
     *  are expected to be received
     * @param requestCallback Callback that allow to sign the request objects
     * @param metadata The authorisation metadata of the OP
     * @param clientId The identifier of the OP
     */
    constructor(redirectUri, 
    // For now, support for JWT. TODO: EXPAND SUPPORT TO JLD
    requestCallback, metadata, clientId) {
        this.redirectUri = redirectUri;
        this.requestCallback = requestCallback;
        this.metadata = metadata;
        this.clientId = clientId;
    }
    // TODO: DERIVE FROM CREDENTIAL OFFER FOR ISSUER STATE AND EVEN AUTHZ DETAILS
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
    createBaseAuthzRequest(url, requestLocation, response_type, // Most probably could be set to "code"
    authzDetails, scope, audience, pkceChallenge) {
        return __awaiter(this, void 0, void 0, function* () {
            let code_challenge, code_challenge_method, code_verifier;
            if (pkceChallenge) {
                code_challenge = pkceChallenge.code_challenge;
                code_challenge_method = pkceChallenge.code_challenge_method;
            }
            else {
                code_verifier = generateRandomString(DEFAULT_PKCE_LENGTH);
                code_challenge = yield generateChallenge(code_verifier);
                code_challenge_method = "S256"; // TODO: Define new type
            }
            const hasParams = url.includes("?");
            const state = uuidv4();
            const authzBaseRequest = new AuthzRequestBuilder(response_type, this.clientId, this.redirectUri)
                .withScope(scope)
                .withMetadata(this.metadata)
                .addAuthzDetails(authzDetails)
                .withCodeChallenge(code_challenge, code_challenge_method)
                .withState(state)
                .build();
            let location;
            let result;
            switch (requestLocation) {
                case AuthzRequestLocation.JWT_OBJECT:
                    const request = yield this.requestCallback(authzBaseRequest, audience);
                    location = `${url}${hasParams ? "&" : "/?"}${querystring.stringify(Object.assign(Object.assign({}, authzBaseRequest), { request }))}`;
                    result = { url: location, state, jwt: request };
                    break;
                case AuthzRequestLocation.PLAIN_REQUEST:
                    location = `${url}${hasParams ? "&" : "/?"}${querystring.stringify(authzBaseRequest)}`;
                    result = { url: location, state };
                    break;
            }
            if (code_verifier) {
                result.code_verifier = code_verifier;
            }
            return result;
        });
    }
    createIdTokenReponse() {
    }
    createVpTokenResponse() {
    }
    verifyIdTokenRequest() {
    }
    verifyVpTokenResponse() {
    }
    verifyAuthzResponse() {
    }
}
