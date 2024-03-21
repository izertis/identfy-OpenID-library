import { JWK, importJWK, jwtVerify } from "jose";
import * as jwt from "jsonwebtoken";
import { InvalidToken } from "../classes/index.js";

/**
 * Deserialize a JWT, which allows to obtain its header, payload and signature
 * @param jsonWebtoken The token to deserialize/decode
 * @returns The header, payload and signature of the token provided
 * @throws if the token provided is invalid for decoding
 */
export function decodeToken(
  jsonWebtoken: string,
): jwt.Jwt {
  const result = jwt.decode(jsonWebtoken, { complete: true });
  if (!result) {
    throw new InvalidToken("Invalid JWT for decoding");
  }
  return result;
}

/**
 * Verify the signature of a JWT and its "exp" and "aud" attributes
 * @param token The token to verify
 * @param publicKeyJWK The public key that should verify the token
 * @param audience The expected audience of the token
 * @throws if the signature verification failed, the token is expired 
 * or the audience is not the expected
 */
export async function verifyJwtWithExpAndAudience(
  token: string,
  publicKeyJWK: JWK,
  audience?: string
) {
  const publicKey = await importJWK(publicKeyJWK);
  const payload = await jwtVerify(token, publicKey, { clockTolerance: 5 });
  if (!payload.payload.exp || payload.payload.exp < Math.floor(Date.now() / 1000)) {
    throw new InvalidToken("JWT is expired or does not have exp parameter");
  }
  if (audience) {
    if (!payload.payload.aud || payload.payload.aud !== audience) {
      throw new InvalidToken("JWT audience is invalid or is not defined");
    }
  }
}

/**
 * Obtain the DID associated with a token from the "iss" or "kid" attribute
 * @param kid The "kid" attribute of the header of the token
 * @param iss The "iss" attribute of the payload of the token
 * @returns The DID of the issuer of the token
 * @throws If it's not possible to extract a DID from the kid attribute and 
 * "iss" is not present or is not a DID
 */
export function obtainDid(kid: string, iss?: string): string {
  if (iss && iss.startsWith("did")) {
    return iss;
  }
  if (!kid.startsWith("did")) {
    throw new InvalidToken(`Can't extract did from "kid" parameter`);
  }
  return kid.trim().split("#")[0]
}