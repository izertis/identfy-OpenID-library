import {
  CredentialOffer,
  CredentialOfferGrants,
  CredentialsOfferData
} from '../interfaces/credential_offer.interface.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * Builder class for CredentialOffer
 */
export class CredentialOfferBuilder {
  private credentials: CredentialsOfferData[] = [];
  private grants?: CredentialOfferGrants;

  /**
   * Constructor for CredentialOfferBuilder
   * @param credential_issuer The URI of the credential issuer
   */
  constructor(
    private credential_issuer: string
  ) { }

  /**
   * Generates a builder with the required data for an 
   * authorizeRequest for the In-Time flow
   * @param credential_issuer The value of "credential_issuer" attribute
   * @param issuer_state The state of the issuer to include in the grant specification
   * @returns This object
   */
  static authorizeCredentialOffer(
    credential_issuer: string,
    issuer_state?: string
  ): CredentialOfferBuilder {
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
  static preAuthorizeCredentialOffer(
    credential_issuer: string,
    pinRequired: boolean,
    preCode?: string
  ): CredentialOfferBuilder {
    return new CredentialOfferBuilder(credential_issuer).withPreAuthGrant(pinRequired, preCode);
  }

  /**
   * Add credential information to include in the Offer
   * @param credentialData The credential information to include in the offer
   * @returns This object
   */
  addCredential(credentialData: CredentialsOfferData): CredentialOfferBuilder {
    this.credentials.push(credentialData);
    return this;
  }

  /**
   * Add data related to the "authorization_code" grant in the offer
   * @param issuer_state The state of the issuer to include in the offer
   * @returns This object
   */
  withAuthGrant(issuer_state?: string): CredentialOfferBuilder {
    if (!issuer_state) {
      issuer_state = uuidv4();
    }
    if (!this.grants) {
      this.grants = { authorization_code: { issuer_state } };
    } else {
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
  withPreAuthGrant(pinRequired: boolean, preCode?: string): CredentialOfferBuilder {
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
    } else {
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
  build(): CredentialOffer {
    return {
      credential_issuer: this.credential_issuer,
      credentials: this.credentials,
      grants: this.grants
    }
  }
}
