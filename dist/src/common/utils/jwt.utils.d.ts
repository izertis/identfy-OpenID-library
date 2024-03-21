import { JWK } from "jose";
import * as jwt from "jsonwebtoken";
/**
 * Deserialize a JWT, which allows to obtain its header, payload and signature
 * @param jsonWebtoken The token to deserialize/decode
 * @returns The header, payload and signature of the token provided
 * @throws if the token provided is invalid for decoding
 */
export declare function decodeToken(jsonWebtoken: string): jwt.Jwt;
/**
 * Verify the signature of a JWT and its "exp" and "aud" attributes
 * @param token The token to verify
 * @param publicKeyJWK The public key that should verify the token
 * @param audience The expected audience of the token
 * @throws if the signature verification failed, the token is expired
 * or the audience is not the expected
 */
export declare function verifyJwtWithExpAndAudience(token: string, publicKeyJWK: JWK, audience?: string): Promise<void>;
/**
 * Obtain the DID associated with a token from the "iss" or "kid" attribute
 * @param kid The "kid" attribute of the header of the token
 * @param iss The "iss" attribute of the payload of the token
 * @returns The DID of the issuer of the token
 * @throws If it's not possible to extract a DID from the kid attribute and
 * "iss" is not present or is not a DID
 */
export declare function obtainDid(kid: string, iss?: string): string;
