import { W3CVerifiableCredentialFormats } from "../formats/index.js";

/**
 * Defines the Grant pre-authorize_code for a Credential Offer in
 * accordance to OID4VCI
 */
export interface GrantPreAuthorizeCode {
  "pre-authorized_code": string;
  user_pin_required: boolean;
}

/**
 * Defines the Grant authorize_code for a Credential Offer in
 * accordance to OID4VCI
 */
export interface GrantAuthorizationCode {
  issuer_state: string;
}

/**
 * Defines the Grant field for a Credential Offer in
 * accordance to OID4VCI
 */
export interface CredentialOfferGrants {
  authorization_code?: GrantAuthorizationCode;
  "urn:ietf:params:oauth:grant-type:pre-authorized_code"?: GrantPreAuthorizeCode;
}

/**
 * Defines the Trust framework field for a Credential Offer in
 * accordance to OID4VCI
 */
export interface CredentialTrustFramework {
  name: string;
  type: string;
  uri?: string;
}

/**
 * Defines the data of Credential Offer in accordance to OID4VCI
 */
export interface CredentialsOfferData {
  format: W3CVerifiableCredentialFormats;
  types: string[]; // Only for W3C Verifiable Credentials
  trust_framework?: CredentialTrustFramework;
}

/**
 * Defines a Credential Offer in accordance to OID4VCI
 */
export interface CredentialOffer {
  credential_issuer: string;
  credentials: CredentialsOfferData[];
  grants?: CredentialOfferGrants;
}
