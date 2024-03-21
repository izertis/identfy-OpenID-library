import { W3CVerifiableCredentialFormats } from "../formats/index.js"

/**
 * Defines the credential issuer metadata in accordance to OID4VCI
 */
export interface IssuerMetadata {
  credential_issuer: string,
  // Draft 10. In Draft 12 this is a string[]
  authorization_server?: string,
  credential_endpoint: string,
  deferred_credential_endpoint?: string,
  batch_credential_endpoint?: string,
  credentials_supported: CredentialSupported[]
}

/**
 * Defines the credential supported object that can appear 
 * in the issuer metadata in accordance to OID4VCI
 */
export interface CredentialSupported {
  format: W3CVerifiableCredentialFormats,
  id?: string,
  types: string[], // Only for W3C Verifiable Credentials
  display?: VerifiableCredentialDisplay[],
}

/**
 * Defines the display information of a credential
 */
export interface VerifiableCredentialDisplay {
  name: string,
  locale?: string, // RFC 5646
  logo?: JSON,
  url?: string,
  alt_text?: string,
  description?: string,
  background_color?: string, // CSS-Color
  text_color?: string // CSS-Color
}