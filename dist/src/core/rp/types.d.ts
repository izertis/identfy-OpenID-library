import { JWK } from 'jose';
import { JWA_ALGS } from '../../common/constants/index.js';
import { AuthzResponseMode } from '../../common/formats/index.js';
import { AuthzRequest, DIFPresentationDefinition } from '../../common/index.js';
import { VpFormatsSupported } from '../../common/types/index.js';
import { DIDDocument } from 'did-resolver';
import { VpExtractedData } from '../presentations/types.js';
import { JwtPayload } from 'jsonwebtoken';
export interface RpConfiguration {
    /**
     * Expiration time(ms) for ID Tokens. @default 10 minutes
     */
    idTokenExpirationTime: number;
    /**
     * Expiration time(ms) for VP Tokens. @default 10 minutes
     */
    vpTokenExpirationTIme: number;
    /**
     * Expiration time(s) for Challenge Nonce. @default 1 hour
     */
    cNonceExpirationTime: number;
    /**
     * Expiration time(s) for access tokens. @default 1 hour
     */
    accessTokenExpirationTime: number;
}
/**
 * Defines a function type that allows signing a JWT Payload
 * @param payload JWT payload to sign
 * @param supportedSignAlg List of supported signature algorithms,
 *  of which one should be used.
 * @returns The signed object in a string format.
 */
export type TokenSignCallback = (payload: JwtPayload, supportedSignAlg?: JWA_ALGS[]) => Promise<string>;
/**
 * Defines an object type that allows to specify the optional parameters of
 * "createIdTokenRequest" OpenIDReliyingParty method
 */
export type CreateTokenRequestOptionalParams = {
    /**
     * Response mode to specify in the ID Token
     * @defaultValue "direct_post"
     */
    responseMode?: AuthzResponseMode;
    /**
     * Additional payload to include in the JWT
     */
    additionalPayload?: Record<string, any>;
    /**
     * The state to indicate in the JWT
     */
    state?: string;
    /**
     * The expiration time of the JWT. Must be in seconds
     * @defaultValue 1 hour
     */
    expirationTime?: number;
    /**
     * The scope to include in the JWT
     */
    scope?: string;
};
/**
 * Allows to define how to specify the presentation definition in a VP Token Request
 */
export type PresentationDefinitionLocation = {
    type: 'Raw';
    presentationDefinition: DIFPresentationDefinition;
} | {
    type: 'Uri';
    presentationDefinitionUri: string;
};
/**
 * Allows to define the purpose behid a specific Authz Request
 */
export type RequestPurpose = {
    type: 'Issuance';
    verifiedBaseAuthzRequest: VerifiedBaseAuthzRequest;
} | {
    type: 'Verification';
    verifiedBaseAuthzRequest: VerifiedBaseAuthzRequest;
};
export interface VerifiedBaseAuthzRequest {
    /**
     * Client metadata related to supported formats and algorithms that are checked against the PR.
     */
    validatedClientMetadata: ValidatedClientMetadata;
    /**
     * Verified authz request
     */
    authzRequest: AuthzRequest;
    /**
     * JWK used by the service Wallet
     */
    serviceWalletJWK?: JWK;
}
export interface VerifiedIdTokenResponse {
    /**
     * The DID Document of the entity that sign the token
     */
    didDocument?: DIDDocument;
    /**
     * The subject identifier. In most cases coincide with the ID of the DID Document
     */
    subject: string;
    /**
     * The verified token
     */
    token: string;
    /**
     * The authorization code generated
     */
    authzCode?: string;
    /**
     * The expected state by the holder
     */
    state?: string;
    /**
     * The URI in which the holder expects to received the Authz code
     */
    redirectUri?: string;
}
export interface VerifiedVpTokenResponse {
    /**
     * The verified token
     */
    token: string;
    /**
     * The data extracted from the VCs of the VP
     */
    vpInternalData: VpExtractedData;
    /**
     * The authorization code generated
     */
    authzCode?: string;
    /**
     * The expected state by the holder
     */
    state?: string;
    /**
     * The URI in which the holder expects to received the Authz code
     */
    redirectUri?: string;
}
/**
 * Client metadata that has been processed to indicate which formats, signature
 * algorithms and response types are supported.
 */
export interface ValidatedClientMetadata {
    /**
     * Response types supported by the client
     */
    responseTypesSupported: string[];
    /**
     * Signature algorithms supported by both the client and an RP
     */
    idTokenAlg: JWA_ALGS[];
    /**
     * VP formats supported both by the client and by an RP
     */
    vpFormats: VpFormatsSupported;
    /**
     * Authorization endpoint of the client
     */
    authorizationEndpoint: string;
}
