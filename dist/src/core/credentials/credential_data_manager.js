/**
 * Abstract class that defines an interface for interacting with a Verifiable Credential (VC) Issuer.
 * It enables clients to retrieve information related to VCs and handle specific issuance flows
 * such as deferred credential issuance.
 */
export class CredentialDataManager {
    /**
     * Resolves the true subject identifier of a credential. This method can be overridden to support
     * custom subject resolution logic, for example when working with DID URLs or other identifier schemes.
     *
     * @param _accessTokenSubject - The `sub` (subject) claim from the Access Token.
     * @param proofIssuer - The identifier of the entity that signed the proof.
     * @returns The resolved subject identifier.
     */
    async resolveCredentialSubject(_accessTokenSubject, proofIssuer) {
        return proofIssuer;
    }
}
//# sourceMappingURL=credential_data_manager.js.map