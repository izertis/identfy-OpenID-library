import { v4 as uuidv4 } from 'uuid';
/**
 * Builder class for CredentialOffer
 */
export class CredentialOfferBuilder {
    /**
     * Constructor for CredentialOfferBuilder
     * @param credential_issuer The URI of the credential issuer
     */
    constructor(credential_issuer) {
        this.credential_issuer = credential_issuer;
        this.credentials = [];
    }
    /**
     * Generates a builder with the required data for an
     * authorizeRequest for the In-Time flow
     * @param credential_issuer The value of "credential_issuer" attribute
     * @param issuer_state The state of the issuer to include in the grant specification
     * @returns This object
     */
    static authorizeCredentialOffer(credential_issuer, issuer_state) {
        return new CredentialOfferBuilder(credential_issuer).withAuthGrant(issuer_state);
    }
    /**
     * Generates a builder with the required data for an
     * authorizeRequest for the Pre-Authorize flow
     * @param credential_issuer The value of "credential_issuer" attribute
     * @param pinRequired Flag that indicates if a PIN should be required
     * @param preCode The pre-authorize_code to include in the offer
     * @returns This object
     */
    static preAuthorizeCredentialOffer(credential_issuer, pinRequired, preCode) {
        return new CredentialOfferBuilder(credential_issuer).withPreAuthGrant(pinRequired, preCode);
    }
    /**
     * Add credential information to include in the Offer
     * @param credentialData The credential information to include in the offer
     * @returns This object
     */
    addCredential(credentialData) {
        this.credentials.push(credentialData);
        return this;
    }
    /**
     * Add data related to the "authorization_code" grant in the offer
     * @param issuer_state The state of the issuer to include in the offer
     * @returns This object
     */
    withAuthGrant(issuer_state) {
        if (!issuer_state) {
            issuer_state = uuidv4();
        }
        if (!this.grants) {
            this.grants = { authorization_code: { issuer_state } };
        }
        else {
            this.grants.authorization_code = { issuer_state };
        }
        return this;
    }
    /**
     * Add data related to the "pre-authorization_code" grant in the offer
     * @param pinRequired Specify if a PIN would be required
     * @param preCode The "pre-authorization_code" to include in the offer
     * @returns This object
     */
    withPreAuthGrant(pinRequired, preCode) {
        if (!preCode) {
            preCode = uuidv4();
        }
        if (!this.grants) {
            this.grants = {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": preCode,
                    user_pin_required: pinRequired
                }
            };
        }
        else {
            this.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = {
                "pre-authorized_code": preCode,
                user_pin_required: pinRequired
            };
        }
        return this;
    }
    /**
     * Generate CredentialOffer from the data contained in the builder
     * @returns CredentialOffer instance
     */
    build() {
        return {
            credential_issuer: this.credential_issuer,
            credentials: this.credentials,
            grants: this.grants
        };
    }
}
