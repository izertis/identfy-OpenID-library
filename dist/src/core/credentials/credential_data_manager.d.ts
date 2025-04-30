import { Result } from '../../common/classes/index.js';
import { CredentialDataResponse, DeferredCredentialData, InTimeCredentialData } from './types.js';
import { W3CVerifiableCredentialFormats } from '../../common/formats/index.js';
/**
 * Abstract class that defines an interface for interacting with a Verifiable Credential (VC) Issuer.
 * It enables clients to retrieve information related to VCs and handle specific issuance flows
 * such as deferred credential issuance.
 */
export declare abstract class CredentialDataManager {
    /**
     * Retrieves all relevant data associated with a Verifiable Credential (VC), including the credentialSubject,
     * terms of use, and status information.
     *
     * @param types - The types (contexts) of the credential being requested.
     * @param holder - The DID or identifier of the future credential holder.
     * @returns A {@link CredentialDataResponse} containing information necessary for credential issuance.
     */
    abstract getCredentialData(types: string[], holder: string): Promise<CredentialDataResponse>;
    /**
     * Handles the deferred credential flow by exchanging an acceptance token for either a finalized VC
     * (if available) or another acceptance token.
     *
     * This method is typically used when the credential is not immediately issued, and further validation
     * or processing is required before completion.
     *
     * @param acceptanceToken - The token received during the initial deferred flow.
     * @returns A {@link Result} containing either the issued credential data or updated deferred information,
     * or an Error in case of failure.
     */
    abstract deferredExchange(acceptanceToken: string): Promise<Result<(InTimeCredentialData & {
        format: W3CVerifiableCredentialFormats;
        types: string[];
    }) | DeferredCredentialData, Error>>;
    /**
     * Resolves the true subject identifier of a credential. This method can be overridden to support
     * custom subject resolution logic, for example when working with DID URLs or other identifier schemes.
     *
     * @param _accessTokenSubject - The `sub` (subject) claim from the Access Token.
     * @param proofIssuer - The identifier of the entity that signed the proof.
     * @returns The resolved subject identifier.
     */
    resolveCredentialSubject(_accessTokenSubject: string, proofIssuer: string): Promise<string>;
}
