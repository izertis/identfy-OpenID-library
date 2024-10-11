import { ClientAssertionTypes } from "../formats/index.js";
import { GrantType } from "../types/index.js";
/**
 * Defines an Access Token Request in accordance to
 * RFC 6749 "The OAuth 2.0 Authorization Framework" and OID4VCI
 */
export interface TokenRequest {
    grant_type: GrantType;
    client_id: string;
    code?: string;
    code_verifier?: string;
    "pre-authorized_code"?: string;
    user_pin?: string;
    vp_token?: string;
    client_assertion?: string;
    client_assertion_type?: ClientAssertionTypes;
}
