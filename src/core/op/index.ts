import { v4 as uuidv4 } from 'uuid';
import querystring from "querystring";
import {
  AuthzRequestBuilder
} from "../../common/builders/authz/authz_request.builder.js";
import {
  AuthorizationDetails
} from "../../common/interfaces/authz_details.interface.js";
import {
  AuthzRequest,
  AuthzRequestLocation
} from "../../common/interfaces/authz_request.interface.js";
import {
  HolderMetadata,
  ServiceMetadata
} from "../../common/interfaces/client_metadata.interface.js";
import { AuthzResponseType } from "../../common/types/index.js";
import { generateChallenge } from "../../common/utils/pkce.utils.js";
import {
  DEFAULT_PKCE_LENGTH,
  generateRandomString
} from '../../common/index.js';

/**
 * Extended authorisation request
 */
interface AuthzRequestMethodData {
  /**
   * The petition in JWT format.
   */
  jwt?: string,
  /**
   * The URL to send the request to
   */
  url: string,
  /**
   * The state associated with the request
   */
  state: string,
  /**
   * The "code_verifier" that resolves the challenge included 
   * in the request
   */
  code_verifier?: string
}

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
  constructor(
    private redirectUri: string,
    // For now, support for JWT. TODO: EXPAND SUPPORT TO JLD
    private requestCallback: AuthzSignCallback,
    private metadata: ServiceMetadata | HolderMetadata,
    private clientId: string,
  ) {

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
  async createBaseAuthzRequest(
    url: string,
    requestLocation: AuthzRequestLocation,
    response_type: AuthzResponseType, // Most probably could be set to "code"
    authzDetails: AuthorizationDetails,
    scope: string,
    audience: string,
    pkceChallenge?: {
      code_challenge: string,
      code_challenge_method: string
    }
  ): Promise<AuthzRequestMethodData> {
    let code_challenge, code_challenge_method, code_verifier;
    if (pkceChallenge) {
      code_challenge = pkceChallenge.code_challenge;
      code_challenge_method = pkceChallenge.code_challenge_method;
    } else {
      code_verifier = generateRandomString(DEFAULT_PKCE_LENGTH);
      code_challenge = await generateChallenge(code_verifier);
      code_challenge_method = "S256"; // TODO: Define new type
    }
    const hasParams = url.includes("?");
    const state = uuidv4();
    const authzBaseRequest = new AuthzRequestBuilder(
      response_type,
      this.clientId,
      this.redirectUri
    )
      .withScope(scope)
      .withMetadata(this.metadata)
      .addAuthzDetails(authzDetails)
      .withCodeChallenge(code_challenge, code_challenge_method)
      .withState(state)
      .build();
    let location;
    let result: AuthzRequestMethodData;
    switch (requestLocation) {
      case AuthzRequestLocation.JWT_OBJECT:
        const request = await this.requestCallback(authzBaseRequest, audience);
        location = `${url}${hasParams ? "&" : "/?"}${querystring.stringify(
          { ...authzBaseRequest, request } as Record<any, any>)}`;
        result = { url: location, state, jwt: request };
        break;
      case AuthzRequestLocation.PLAIN_REQUEST:
        location = `${url}${hasParams ? "&" : "/?"}${querystring.stringify(authzBaseRequest as Record<any, any>)}`;
        result = { url: location, state };
        break;
    }
    if (code_verifier) {
      result.code_verifier = code_verifier;
    }
    return result;
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

/**
 * Function type that allows to sign an AuthzRequest
 * @param data The request to sign
 * @param target The audience of the request
 * @returns The signed request in string format
 */
export type AuthzSignCallback = (data: AuthzRequest, target: string) => Promise<string>;
