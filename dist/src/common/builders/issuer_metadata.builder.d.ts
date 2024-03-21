import { W3CVerifiableCredentialFormats } from "../formats/index.js";
import { CredentialSupported, IssuerMetadata, VerifiableCredentialDisplay } from '../interfaces/issuer_metadata.interface.js';
/**
 * Builder class for Credential Issuer Metadata
 */
export declare class IssuerMetadataBuilder {
    private credential_issuer;
    private credential_endpoint;
    private imposeHttps;
    private authorization_server?;
    private deferred_credential_endpoint?;
    private batch_credential_endpoint?;
    private credentials_supported;
    /**
     * Constructor of IssuerMetadataBuilder
     * @param credential_issuer URI of the credential issuer
     * @param credential_endpoint Credential issuer endpoint in which credential
     * request should be sended
     * @param imposeHttps Flag that indicates if the builder should check if
     * the provided URL are HTTPS
     * @throws if imposeHttps is true an a not HTTPS URI is provided
     */
    constructor(credential_issuer: string, credential_endpoint: string, imposeHttps?: boolean);
    private assertUrlIsHttps;
    /**
     * Set authorization server paramater for issuer metadata
     * @param url URI of the authorization server
     * @returns This object
     */
    withAuthorizationServer(url: string): IssuerMetadataBuilder;
    /**
     * Set deferred credential endpoint paramater for issuer metadata
     * @param url Endpoint for deferred credentials
     * @returns This object
     */
    withDeferredCredentialEndpoint(url: string): IssuerMetadataBuilder;
    /**
     * Set batch credential endpoint paramater for issuer metadata
     * @param url Endpoint fot batch credentials issuance
     * @returns This object
     */
    withBatchCredentialEndpoint(url: string): IssuerMetadataBuilder;
    /**
     * Add a new credential supported for issuer metadata
     * @param supportedCredential Credential specification
     * @returns This object
     * @throws If the credential already exists
     */
    addCredentialSupported(supportedCredential: CredentialSupported): IssuerMetadataBuilder;
    /**
     * Generate IssuerMetadata from the data contained in the builder
     * @returns IssuerMetadata instance
     */
    build(): IssuerMetadata;
}
/**
 * Builder class for Credential Supported objects in Credential Issuer Metadata
 */
export declare class CredentialSupportedBuilder {
    private format;
    private id?;
    private types;
    private display?;
    /**
     * Set the format of the credential. By default "jwt_vc_json".
     * @param format The W3C VC format
     * @returns This object
     */
    withFormat(format: W3CVerifiableCredentialFormats): CredentialSupportedBuilder;
    /**
     * Set the ID of the credential
     * @param id The id of the credential
     * @returns This object
     */
    withId(id: string): CredentialSupportedBuilder;
    /**
     * Set the types of the credential
     * @param types The types of the credentials
     * @returns This object
     */
    withTypes(types: string[]): CredentialSupportedBuilder;
    /**
     * Add display information for the credential
     * @param display Information of how to display the credential
     * @returns This object
     */
    addDisplay(display: VerifiableCredentialDisplay): CredentialSupportedBuilder;
    /**
     * Generate CredentialSupported from the data contained in this builder
     * @returns CredentialSupported instance
     */
    build(): CredentialSupported;
}
/**
 * Builder for VC display information in CredentialSupported objects
 */
export declare class VerifiableCredentialDisplayBuilder {
    private name;
    /**
     * Constructor of VerifiableCredentialDisplayBuilder
     * @param name String value of a display name for the Credential Issuer.
     */
    constructor(name: string);
    private locale?;
    private logo?;
    private url?;
    private alt_text?;
    private description?;
    private background_color?;
    private text_color?;
    /**
     * Set the locale information of the display information
     * @param locale String value that identifies the language of this object
     * represented as a language tag taken from values defined in BCP47
     * @returns This object
     */
    withLocale(locale: string): VerifiableCredentialDisplayBuilder;
    /**
     * Set the logo information of the display information
     * @param logo Logo information
     * @returns This object
     */
    withLogo(logo: JSON): VerifiableCredentialDisplayBuilder;
    /**
     * Set the "url" attribute of the display information
     * @param url The URL itself
     * @returns This object
     */
    withUrl(url: string): VerifiableCredentialDisplayBuilder;
    /**
     * Set the "alt_text" attribute of the display information
     * @param text The text for the attribute
     * @returns This object
     */
    withAltText(text: string): VerifiableCredentialDisplayBuilder;
    /**
     * Set the "description" attribute of the display information
     * @param description The description to include
     * @returns This object
     */
    withDescription(description: string): VerifiableCredentialDisplayBuilder;
    /**
     * Set the "background_color" attribute of the display information
     * @param color The color to include
     * @returns This object
     */
    withBackgroundColor(color: string): VerifiableCredentialDisplayBuilder;
    /**
     * Set the "text_color" attribute of the display information
     * @param textColor The color to include
     * @returns This object
     */
    withTextColor(textColor: string): VerifiableCredentialDisplayBuilder;
    /**
     * Generate VerifiableCredentialDisplay object from the data contained in the builder
     * @returns VerifiableCredentialDisplay instance
     */
    build(): VerifiableCredentialDisplay;
}
