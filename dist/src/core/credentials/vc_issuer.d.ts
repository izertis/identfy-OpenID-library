import { Resolver } from 'did-resolver';
import { JWK } from 'jose';
import { Jwt } from 'jsonwebtoken';
import { W3CDataModel, W3CVerifiableCredentialFormats } from '../../common/formats/index.js';
import { CredentialRequest } from '../../common/interfaces/credential_request.interface.js';
import { IssuerMetadata } from '../../common/interfaces/issuer_metadata.interface.js';
import { CredentialResponse } from '../../common/interfaces/credential_response.interface.js';
import * as VcIssuerTypes from './types.js';
import { CredentialDataManager } from './credential_data_manager.js';
import { StateManager } from '../state/index.js';
/**
 * Component responsible for issuing W3C Verifiable Credentials
 * following the OID4VCI specification.
 *
 * Supports both immediate and deferred issuance flows. Validates requests,
 * signs credentials, and generates the expected credential response objects.
 */
export declare class W3CVcIssuer {
    private metadata;
    private didResolver;
    private issuerDid;
    private signCallback;
    private credentialDataManager;
    private vcTypesContextRelationship?;
    private nonceManager;
    /**
     * Initializes the W3CVcIssuer.
     *
     * @param metadata - Metadata of the credential issuer (as defined in OID4VCI).
     * @param didResolver - Resolver used to fetch DID Documents.
     * @param issuerDid - DID of the entity issuing the credentials.
     * @param signCallback - Callback used to sign the VC before returning it.
     * @param stateManager - Manages challenge nonces and issuance-related state.
     * @param credentialDataManager - Provides subject data for the VC or deferred flow logic.
     * @param vcTypesContextRelationship - (Optional) Mapping from VC types to additional context URLs.
     */
    constructor(metadata: IssuerMetadata, didResolver: Resolver, issuerDid: string, signCallback: VcIssuerTypes.VcSignCallback, stateManager: StateManager, credentialDataManager: CredentialDataManager, vcTypesContextRelationship?: Record<string, string> | undefined);
    /**
     * Verifies a JWT Access Token received from a client.
     *
     * This method checks the token's validity (signature, expiration, audience)
     * using the public key of the authorization server. Optionally, it can also
     * apply custom logic through a callback to further validate the token's payload.
     *
     * @param token - JWT Access Token in string format.
     * @param publicKeyJwkAuthServer - Public JWK of the authorization server used to verify the signature.
     * @param tokenVerifyCallback - (Optional) Additional logic to validate the decoded token (e.g. claims).
     * @returns A decoded JWT object if verification succeeds.
     * @throws {InvalidToken} If the token is invalid, expired, has wrong audience, or fails custom validation.
     */
    verifyAccessToken(token: string, publicKeyJwkAuthServer: JWK, tokenVerifyCallback?: VcIssuerTypes.AccessTokenVerifyCallback): Promise<Jwt>;
    /**
     * Generates a Credential Response in compliance with the OpenID for Verifiable Credential Issuance (OID4VCI) specification.
     *
     * This method processes a credential request by:
     * - Verifying the associated control proof using a previously issued `c_nonce`.
     * - Validating that the proof signer matches the Access Token subject (when required).
     * - Ensuring the requested credential types are authorized by the Access Token.
     * - Issuing either a Verifiable Credential (VC) or a deferred credential code, depending on the flow.
     *
     * @param accessToken - Decoded Access Token containing authorization to issue the requested VC.
     * @param credentialRequest - The credential request payload received from the client.
     * @param dataModel - Indicates which W3C VC Data Model version to use (v1 or v2).
     * @returns A {@link CredentialResponse} containing either a signed VC or an acceptance token for deferred issuance.
     * @throws {InvalidCredentialRequest | InvalidToken | InvalidProof | InternalNonceError}
     * If the request is malformed, unauthorized, or if the proof or nonce is invalid.
     */
    generateCredentialResponse(acessToken: Jwt, credentialRequest: CredentialRequest, dataModel: W3CDataModel): Promise<CredentialResponse>;
    private credentialResponseMatch;
    /**
     * Generates a Verifiable Credential (VC) without requiring an Access Token.
     *
     * This method is typically used in direct issuance flows (e.g., internal tools, testing, or
     * controlled environments) where no authorization layer is applied.
     *
     * It directly triggers the generation of a credential using the provided holder DID, types,
     * format, and data model version. The VC content is obtained through the configured
     * {@link CredentialDataManager}.
     *
     * @param did - The subject identifier (DID) of the future holder of the VC.
     * @param dataModel - Indicates whether the credential should follow the W3C VC Data Model v1 or v2.
     * @param types - The array of types the credential must include.
     * @param format - The serialization format of the credential (e.g., `ldp_vc`, `jwt_vc_json`, etc).
     * @returns A {@link CredentialResponse} containing a signed VC.
     * @throws {InvalidCredentialRequest} If the combination of types and format is not supported.
     */
    generateVcDirectMode(did: string, dataModel: W3CDataModel, types: string[], format: W3CVerifiableCredentialFormats): Promise<CredentialResponse>;
    private generateCredentialTimeStamps;
    private generateVcId;
    private generateW3CDataForV1;
    private generateW3CDataForV2;
    private extendsVcContext;
    private generateW3CCredential;
    /**
     * Exchanges a previously issued deferred acceptance token for a Verifiable Credential (VC).
     *
     * This method handles the final step of a deferred issuance flow. The client presents a
     * previously issued `acceptance_token`, and this method either returns the issued credential
     * (if ready), or provides a new `acceptance_token` to poll again later.
     *
     * Internally, it delegates the resolution of credential readiness and subject data to the
     * configured {@link CredentialDataManager}.
     *
     * @param acceptanceToken - The token received in a previous deferred response, identifying the pending VC.
     * @param dataModel - The W3C VC Data Model version to use (`v1` or `v2`).
     * @returns A {@link CredentialResponse} containing either the signed VC or a new deferred token.
     * @throws {InvalidToken} If the provided token is invalid, expired, or unrecognized.
     */
    exchangeAcceptanceTokenForVc(acceptanceToken: string, dataModel: W3CDataModel): Promise<CredentialResponse>;
    private checkCredentialTypesAndFormat;
}
