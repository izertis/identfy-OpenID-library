import { AuthzResponseType } from "../types/index.js";
import { AuthorizationDetails } from "./authz_details.interface.js";
import {
  HolderMetadata,
  ServiceMetadata
} from "./client_metadata.interface.js";

/**
 * Defines an Authorization Request in accordance to
 * RFC 6749 "The OAuth 2.0 Authorization Framework" and
 * RFC 9396 "OAuth 2.0 Rich Authorization Requests"
 */
export interface AuthzRequest {
  response_type: AuthzResponseType;
  client_id: string;
  redirect_uri: string;
  scope: string;
  issuer_state?: string;
  state?: string;
  authorization_details?: AuthorizationDetails[];
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  client_metadata?: HolderMetadata | ServiceMetadata
}

/**
 * Defines an Authorization Request with its own data encapsulated in a JWT.
 * This is the case when the request must be signed.
 */
export interface AuthzRequestWithJWT extends AuthzRequest {
  request?: string
};

/**
 * Defines in which location the request for authorisation should be included:
 * - PLAIN_REQUEST: The request is not signed and travels in the same HTTP 
 * request as in the form of parameters.
 * - JWT_OBJECT: The request is signed and represented as a JWT
 */
export enum AuthzRequestLocation {
  PLAIN_REQUEST,
  JWT_OBJECT,
}
