/**
 * THe valid formats for a W3C VC
 */
export type W3CVerifiableCredentialFormats = "jwt_vc_json" | "jwt_vc_json-ld" | "ldp_vc" | "jwt_vc";
/**
 * The valid formats for a W3C VP
 */
export type W3CVerifiablePresentationFormats = "jwt_vp_json" | "ldp_vp" | "jwt_vp";
/**
 * Valid response_modes for a authorisation response
 */
export type AuthzResponseMode = "direct_post" | "post" | "query" | "fragment";
/**
 * W3C VC Data models version number
 */
export declare enum W3CDataModel {
    V1 = 0,
    V2 = 1
}
