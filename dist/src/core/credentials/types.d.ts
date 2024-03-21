import { W3CVerifiableCredentialFormats } from "../../common/formats/index.js";
import { W3CCredentialStatus, W3CSingleCredentialSubject, W3CVcSchemaDefinition, W3CVerifiableCredential } from "../../common/interfaces/w3c_verifiable_credential.interface.js";
import { CompactVc, VerificationResult } from "../../common/types/index.js";
import { JWK } from "jose";
import { JwtHeader, JwtPayload } from "jsonwebtoken";
/**
 * Function type that allows to verify the contents, but no the
 * signature, of an acess token
 * @param header The JWT header of the token
 * @param payload The JWT payload of the token
 * @returns Verification that result that specify if it was successful
 * and an optional error message
 */
export type AccessTokenVerifyCallback = (header: JwtHeader, payload: JwtPayload) => Promise<VerificationResult>;
/**
 * Function type that allows to sign a W3C credential in a specific format
 * @param format The format of the VC
 * @param vc The VC to sign
 * @returns A signed VC in W3C or compact(string) format
 */
export type VcSignCallback = (format: W3CVerifiableCredentialFormats, vc: W3CVerifiableCredential | JwtPayload) => Promise<W3CVerifiableCredential | CompactVc>;
/**
 * Function type that allows to exchange a deferred code for credential data
 * @param acceptanceToken The deferred code
 * @returns Credential data or a new deferred code
 */
export type DeferredExchangeCallback = (acceptanceToken: string) => Promise<ExtendedCredentialDataOrDeferred | {
    error: string;
}>;
/**
 * Contains the subject data of a VC along with its type and format,
 * It can also contains a deferred code
 */
export interface ExtendedCredentialDataOrDeferred extends CredentialDataOrDeferred {
    /**
     * The types of a VC
     */
    types: string[];
    /**
     * The format of a VC
     */
    format: W3CVerifiableCredentialFormats;
}
/**
 * Function type that allows to recover the challenge nonce expected for a control proof
 * @param clientId: The client identifier in a control proof
 * @returns The expected challenge nonce in string format
 */
export type ChallengeNonceRetrieval = (clientId: string) => Promise<string>;
/**
 * Function type that allows to recover the VC schema
 * @param types Types of the VC
 * @return The W3C schema definition of VC
 */
export type GetCredentialSchema = (types: string[]) => Promise<W3CVcSchemaDefinition[]>;
/**
 * Function type that allows to recover the subject data of a VC
 * @param types The types of the VC to generate
 * @param holder The identifier of the subject
 * @return The credential subject data or a deferred code
 */
export type GetCredentialData = (types: string[], holder: string) => Promise<CredentialDataOrDeferred>;
/**
 * Contains the subject data of a VC or a deferred code
 */
export interface CredentialDataOrDeferred {
    /**
     * The subject data of a credential
     */
    data?: W3CSingleCredentialSubject;
    /**
     * A deferred code that can be exchange for a VC
     */
    deferredCode?: string;
}
/**
 *
 */
export interface GenerateCredentialReponseOptionalParams extends BaseOptionalParams {
    tokenVerification?: {
        publicKeyJwkAuthServer: JWK;
        tokenVerifyCallback: AccessTokenVerifyCallback;
    };
}
/**
 * Optional parameters that can be used in the generateCredentialResponse
 * and exchangeAcceptanceTokenForVc VcIssuer methods
 */
export interface BaseOptionalParams {
    /**
     * Function that allows to obtain until which date the VC to generate is valid.
     * If not specified, then the VC won't have an expiration date
     * @param types The types of the credential
     * @returns The expiration time in UTC and in ISO string format
     */
    getValidUntil?: (types: string[]) => Promise<string>;
    /**
     * Function type that allows to generate the "credentialStatus" attribute of a VC
     * @param types Types of the VC to generate
     * @param credentialId The identifier of the VC
     * @param holder The identifier of the holder of the VC
     */
    getCredentialStatus?: (types: string[], credentialId: string, holder: string) => Promise<W3CCredentialStatus>;
    /**
     * Challenge nonce to send with the credential response
     */
    cNonceToEmploy?: string;
    /**
     * Expiration time of the challenge nonce to send with the credential response
     */
    cNonceExp?: number;
}
