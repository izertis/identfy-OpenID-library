/**
 * Defines an Access Token Response in accordance to
 * RFC 6749 "The OAuth 2.0 Authorization Framework" and OID4VCI
 */
export interface TokenResponse {
    access_token: string;
    id_token?: string;
    token_type: "bearer";
    expires_in: number;
    c_nonce: string;
    c_nonce_expires_in: number;
}
