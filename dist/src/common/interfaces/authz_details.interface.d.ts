import { W3CVerifiableCredentialFormats } from '../formats/index.js';
/**
 * Defines the details of an Authorization Request in accordance to
 * OID4VCI and RFC 9396 "OAuth 2.0 Rich Authorization Requests"
 */
export interface AuthorizationDetails {
    type: string;
    format?: W3CVerifiableCredentialFormats;
    types?: string[];
    locations?: string[];
    actions?: string[];
    datatypes?: string[];
    identifier?: string;
    privileges?: string[];
}
