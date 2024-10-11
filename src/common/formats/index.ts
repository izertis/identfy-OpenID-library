// "JWT_VC is a old identifier. It's there for compatibility"
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#format-profiles
/**
 * THe valid formats for a W3C VC
 */
export type W3CVerifiableCredentialFormats = "jwt_vc_json" |
  "jwt_vc_json-ld" |
  "ldp_vc" |
  "jwt_vc";
// "JWT_VP is a old identifier. It's there for compatibility"
/**
 * The valid formats for a W3C VP
 */
export type W3CVerifiablePresentationFormats = "jwt_vp_json" |
  "ldp_vp" |
  "jwt_vp";
// OAuth 2.0 Multiple Response Type Encoding Practices
/**
 * Valid response_modes for a authorisation response
 */
export type AuthzResponseMode = "direct_post" | "post" | "query" | "fragment";
/**
 * W3C VC Data models version number
 */
export enum W3CDataModel {
  V1,
  V2
}

export type ClientAssertionTypes = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
