import { CredentialOffer, CredentialsOfferData } from '../interfaces/credential_offer.interface.js';
/**
 * Builder class for CredentialOffer
 */
export declare class CredentialOfferBuilder {
    private credential_issuer;
    private credentials;
    private grants?;
    /**
     * Constructor for CredentialOfferBuilder
     * @param credential_issuer The URI of the credential issuer
     */
    constructor(credential_issuer: string);
    /**
     * Generates a builder with the required data for an
     * authorizeRequest for the In-Time flow
     * @param credential_issuer The value of "credential_issuer" attribute
     * @param issuer_state The state of the issuer to include in the grant specification
     * @returns This object
     */
    static authorizeCredentialOffer(credential_issuer: string, issuer_state?: string): CredentialOfferBuilder;
    /**
     * Generates a builder with the required data for an
     * authorizeRequest for the Pre-Authorize flow
     * @param credential_issuer The value of "credential_issuer" attribute
     * @param pinRequired Flag that indicates if a PIN should be required
     * @param preCode The pre-authorize_code to include in the offer
     * @returns This object
     */
    static preAuthorizeCredentialOffer(credential_issuer: string, pinRequired: boolean, preCode?: string): CredentialOfferBuilder;
    /**
     * Add credential information to include in the Offer
     * @param credentialData The credential information to include in the offer
     * @returns This object
     */
    addCredential(credentialData: CredentialsOfferData): CredentialOfferBuilder;
    /**
     * Add data related to the "authorization_code" grant in the offer
     * @param issuer_state The state of the issuer to include in the offer
     * @returns This object
     */
    withAuthGrant(issuer_state?: string): CredentialOfferBuilder;
    /**
     * Add data related to the "pre-authorization_code" grant in the offer
     * @param pinRequired Specify if a PIN would be required
     * @param preCode The "pre-authorization_code" to include in the offer
     * @returns This object
     */
    withPreAuthGrant(pinRequired: boolean, preCode?: string): CredentialOfferBuilder;
    /**
     * Generate CredentialOffer from the data contained in the builder
     * @returns CredentialOffer instance
     */
    build(): CredentialOffer;
}
