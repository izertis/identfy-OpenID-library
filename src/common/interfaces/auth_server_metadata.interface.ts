import { JWA_ALGS } from "../constants/index.js";
import { GrantType, VpFormatsSupported } from "../types/index.js";

/**
 * Defines the metadata of an Authorization Server in accordance to 
 * RFC 8414 "OAuth 2.0 Authorization Server Metadata"
 */
export interface AuthServerMetadata {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  presentation_definition_endpoint?: string;
  jwks_uri?: string;
  scopes_supported?: string[];
  response_types_supported: string[];
  response_modes_supported?: string[];
  grant_types_supported?: GrantType[];
  subject_types_supported?: string[];
  id_token_signing_alg_values_supported?: JWA_ALGS[];
  request_object_signing_alg_values_supported?: JWA_ALGS[];
  request_parameter_supported?: boolean;
  request_uri_parameter_supported?: boolean;
  token_endpoint_auth_methods_supported?: string[];
  vp_formats_supported?: VpFormatsSupported;
  subject_syntax_types_supported?: string[];
  subject_trust_frameworks_supported?: string[];
  id_token_types_supported?: string[]
}
