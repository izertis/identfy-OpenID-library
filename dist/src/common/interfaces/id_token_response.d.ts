import { JwtPayload } from "jsonwebtoken";
/**
 * Defines an authorization response for the response type "id_token"
 */
export interface IdTokenResponse {
    id_token: string;
    [key: string]: any;
}
/**
 * Defines the payload of an ID Token
 */
export interface IdTokenResponsePayload extends JwtPayload {
    state?: string;
    nonce: string;
}
