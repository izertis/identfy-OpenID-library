import { W3CVerifiableCredentialFormats } from '../../common/formats/index.js';
import { W3CCredentialStatus, W3CSingleCredentialSubject, W3CTermsOfUse, W3CVcSchemaDefinition, W3CVerifiableCredential } from '../../common/interfaces/w3c_verifiable_credential.interface.js';
import { CompactVc, VerificationResult } from '../../common/types/index.js';
import { JwtHeader, JwtPayload } from 'jsonwebtoken';
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
export type CredentialDataResponse = InTimeCredentialData | DeferredCredentialData;
export interface InTimeCredentialData {
    type: 'InTime';
    /**
     * The subject data of a credential
     */
    data: W3CSingleCredentialSubject;
    /**
     * The schema of the VC
     */
    schema: W3CVcSchemaDefinition | W3CVcSchemaDefinition[];
    /**
     * The credential status information of the VC
     */
    status?: W3CCredentialStatus | W3CCredentialStatus[];
    /**
     * The terms of use information of the VC
     */
    termfOfUse?: W3CTermsOfUse | W3CTermsOfUse[];
    /**
     * The metadata of the VC
     */
    metadata: CredentialMetadata;
}
export interface DeferredCredentialData {
    type: 'Deferred';
    /**
     * A deferred code that can be exchange for a VC
     */
    deferredCode?: string;
}
export interface CredentialMetadata {
    /** The expiration time in UTC and in ISO format. Can't be combined with expiresIn */
    validUntil?: string;
    /** For how long will be valid the VC. Can't be combined with validUntil */
    expiresInSeconds?: number;
    /** When the VC will be valid */
    nbf?: string;
    /** Issuance in ISO format. If not defined, the current datetime is taken */
    iss?: string;
}
