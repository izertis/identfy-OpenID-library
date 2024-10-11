import { JWA_ALGS } from "../constants/index.js";
import {
  W3CVerifiableCredentialFormats,
  W3CVerifiablePresentationFormats
} from "../formats/index.js";

// RFC 6749 Section 3.1.1
// OAuth 2.0 Multiple Response Type Encoding Practices Section 3
// OID4VP Section 5.4
/**
 * Valid response types for an authorisation response
 */
export type AuthzResponseType = "code" | "token" | "id_token" | "vp_token";
/**
 * Valid grant types for a token request
 */
export type GrantType = "authorization_code" |
  "urn:ietf:params:oauth:grant-type:pre-authorized_code" |
  "vp_token";
/**
 * Valid control proof types
 */
export type ControlProofType = "jwt";
/**
 * Supported formats for a VP
 */
export type VpFormatsSupported = {
  [key in W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats]?: { alg_values_supported: JWA_ALGS[]; };
};
/**
 * Compact VC representation
 */
export type CompactVc = string;
/**
 * The result of a verification process, with an optional error message
 */
export type VerificationResult = { valid: boolean, error?: string };
