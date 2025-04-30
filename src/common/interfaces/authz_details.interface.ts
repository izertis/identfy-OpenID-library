import {W3CVerifiableCredentialFormats} from '../formats/index.js';

/**
 * Defines the details of an Authorization Request in accordance to
 * OID4VCI and RFC 9396 "OAuth 2.0 Rich Authorization Requests"
 */
export interface AuthorizationDetails {
  // OAuth 2.0 Rich Authorization Requests Section 2
  type: string; // OID4VCI Section 5.1.1
  format?: W3CVerifiableCredentialFormats; // OID4VCI Section 5.1.1
  types?: string[];
  locations?: string[];
  actions?: string[];
  datatypes?: string[];
  identifier?: string;
  privileges?: string[];
}
