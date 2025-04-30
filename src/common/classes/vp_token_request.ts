import {AuthzResponseMode} from '../formats/index.js';
import {DIFPresentationDefinition} from '../interfaces/presentation_definition.interface.js';

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
  constructor(
    public requestParams: VpTokenRequestParams,
    public request: string,
    private clientAuthorizationEndpoint: string,
  ) {}

  /**
   * Encode the request in URL format
   * @returns The request in URL format
   */
  toUri(): string {
    const data = {...this.requestParams};
    delete data.presentation_definition;
    delete data.presentation_definition_uri;
    return `${this.clientAuthorizationEndpoint}?${new URLSearchParams(
      Object.entries({
        ...(data as Omit<
          VpTokenRequestParams,
          'presentation_definition' | 'presentation_definition_uri'
        >),
        request: this.request,
      }),
    ).toString()}`;
  }
}

/**
 * Parameters of a VP Token Request
 */
export interface VpTokenRequestParams {
  response_type: 'vp_token';
  presentation_definition?: DIFPresentationDefinition;
  presentation_definition_uri?: string;
  client_id: string;
  scope: string;
  redirect_uri: string;
  response_mode?: AuthzResponseMode;
  state?: string;
  nonce?: string;
}
