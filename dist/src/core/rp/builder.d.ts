import { Resolver } from 'did-resolver';
import { Result } from '../../common/classes/result.js';
import { AuthServerMetadata, AuthorizationDetails, HolderMetadata } from '../../common/index.js';
import { CredentialAdditionalVerification } from '../presentations/types.js';
import { RpConfiguration, TokenSignCallback } from './types.js';
import { StateManager } from '../state/index.js';
import { OpenIDReliyingParty } from './index.js';
/**
 * Step builder that can be used to create an instance of a Reliying Party
 */
export declare class OpenIdRPStepBuilder {
    private metadata;
    private issuerStateCallback;
    private authzDetailsVerificationCallback;
    private credentialExternalVerification;
    private scopeVerificationFlag;
    private subjectComparison;
    private preAuthCallback;
    private generalConfiguration;
    constructor(metadata: AuthServerMetadata);
    /**
     * Allows to overwrite the default expiration time for ID Token Request
     * @param time The new expieration time in ms
     * @returns The same instance of the step builder
     */
    setIdTokenExpirationTime(time: number): this;
    /**
     * Allows to overwrite the default expiration time for VP Token Request
     * @param time The new expieration time in ms
     * @returns The same instance of the step builder
     */
    setVpTokenExpirationTime(time: number): this;
    /**
     * Allows to overwrite the default expiration time for Challenge nonces
     * @param time The new expieration time in seconds
     * @returns The same instance of the step builder
     */
    setCNonceExpirationTime(time: number): this;
    /**
     * Allows to overwrite the default expiration time for Access token
     * @param time The new expieration time in ms
     * @returns The same instance of the step builder
     */
    setAccessTokenExpirationTime(time: number): this;
    /**
     * Allows to establish a callback to handle token request that use the pre-auth
     * grant type. If not defined, all requests of this type will be rejected
     * @param callback The callback to handle the Pre-Auth Code. A "result" objet with the
     * real clientId of the user is expected
     * @returns The same instance of the step builder
     */
    withPreAuthCallback(callback: (clientId: string | undefined, preCode: string, pin?: string) => Promise<Result<string, Error>>): this;
    /**
     * Allows to establish a callback to handle the "issuer state" parameter of auth request.
     * If not defined, all issuer state will be ignored.
     * @param callback The callback to handle the issuer_state parameter
     * @returns The same instance of the step builder
     */
    withIssuerStateVerification(callback: (state: string) => Promise<Result<null, Error>>): this;
    /**
     * Allows to establish a callback to perfom a specific verification of the Authz details
     * of Authz Request. If not defined, only a basic verification will be perfomed, in which the
     * validity of the contentes of the details are not analyzed.
     * @param callback The callback to handle the authz details
     * @returns The same instance of the step builder
     */
    withAuthzDetailsVerification(callback: (authDetails: AuthorizationDetails) => Promise<Result<null, Error>>): this;
    /**
     * Allows to set a flag to perfome scope verification against authz server metadata
     * @returns The same instance of the step builder
     */
    withScopeVerification(): this;
    /**
     * Allows to set a callback to vefify the extracted data of the VCs in a VP
     * according to the presentation definition
     * @param callback The callback that handle the verification
     * @returns The same instance of the step builder
     */
    withVpCredentialExternalVerification(callback: CredentialAdditionalVerification): this;
    /**
     * Allows to overwrite the comparison function used to compared clientID in
     * different stages of the OpenID protocol. For example, if a holder ask for AuthzCode
     * throught a Base Authz Request, then its clientID would be saved among other data.
     * When the holder delivers an VP Token or ID Token, or ask for a Access Token, the
     * clientID would be compared to that used in the previous stages. The default behaviour
     * is a straight comparison using the "===" operator. In general, there is no need to modify
     * the default behaviour, unless the DID that is been used requires it, for example, by using
     * DID URL syntax.
     * @param resolutor The comparison callback
     * @returns The same instance of the step builder
     */
    withCustomSubjectComparison(resolutor: (firstId: string, secondId: string) => boolean): this;
    /**
     * Allows to specify the default metadata for all holder that establish contact with the
     * authz server. The specified emtadata will repace any omitted parameter by the holder.
     * This method also ends the first stage of the step builder.
     * @param metadata The metadata to use
     * @returns The next stage of the step builder, focused on the DID Resolvers
     */
    setDefaultHolderMetadata(metadata: HolderMetadata): OpenIdStepBuilderHolderMetadataStage;
}
declare class OpenIdStepBuilderHolderMetadataStage {
    private generalConfiguration;
    private metadata;
    private issuerStateCallback;
    private authzDetailsVerificationCallback;
    private credentialExternalVerification;
    private scopeVerificationFlag;
    private holderMetadata;
    private subjectComparison;
    private preAuthCallback;
    constructor(generalConfiguration: RpConfiguration, metadata: AuthServerMetadata, issuerStateCallback: undefined | ((state: string) => Promise<Result<null, Error>>), authzDetailsVerificationCallback: undefined | ((authDetails: AuthorizationDetails) => Promise<Result<null, Error>>), credentialExternalVerification: undefined | CredentialAdditionalVerification, scopeVerificationFlag: boolean, holderMetadata: HolderMetadata, subjectComparison: (firstId: string, secondId: string) => boolean, preAuthCallback?: undefined | ((clientId: string | undefined, preCode: string, pin?: string) => Promise<Result<string, Error>>));
    /**
     * Allows to set the DID Resolver to use by the RP
     * @param didResolver The DID Resolver to use
     * @returns The next stage of the step builder
     */
    withDidResolver(didResolver: Resolver): OpenIdStepBuilderResolverStage;
}
declare class OpenIdStepBuilderResolverStage {
    private generalConfiguration;
    private metadata;
    private issuerStateCallback;
    private authzDetailsVerificationCallback;
    private credentialExternalVerification;
    private scopeVerificationFlag;
    private holderMetadata;
    private didResolver;
    private subjectComparison;
    private preAuthCallback;
    constructor(generalConfiguration: RpConfiguration, metadata: AuthServerMetadata, issuerStateCallback: undefined | ((state: string) => Promise<Result<null, Error>>), authzDetailsVerificationCallback: undefined | ((authDetails: AuthorizationDetails) => Promise<Result<null, Error>>), credentialExternalVerification: undefined | CredentialAdditionalVerification, scopeVerificationFlag: boolean, holderMetadata: HolderMetadata, didResolver: Resolver, subjectComparison: (firstId: string, secondId: string) => boolean, preAuthCallback?: undefined | ((clientId: string | undefined, preCode: string, pin?: string) => Promise<Result<string, Error>>));
    /**
     * Allows to set the sign callback for all tokens and request that
     * the RP will generate
     * @param jwtSignCallback The callback to use
     * @returns The next stage of the step builder
     */
    withTokenSignCallback(jwtSignCallback: TokenSignCallback): OpenIdStepBuilderSignStage;
}
declare class OpenIdStepBuilderSignStage {
    private generalConfiguration;
    private metadata;
    private jwtSignCallback;
    private issuerStateCallback;
    private authzDetailsVerificationCallback;
    private credentialExternalVerification;
    private scopeVerificationFlag;
    private holderMetadata;
    private didResolver;
    private subjectComparison;
    private preAuthCallback;
    constructor(generalConfiguration: RpConfiguration, metadata: AuthServerMetadata, jwtSignCallback: TokenSignCallback, issuerStateCallback: undefined | ((state: string) => Promise<Result<null, Error>>), authzDetailsVerificationCallback: undefined | ((authDetails: AuthorizationDetails) => Promise<Result<null, Error>>), credentialExternalVerification: undefined | CredentialAdditionalVerification, scopeVerificationFlag: boolean, holderMetadata: HolderMetadata, didResolver: Resolver, subjectComparison: (firstId: string, secondId: string) => boolean, preAuthCallback?: undefined | ((clientId: string | undefined, preCode: string, pin?: string) => Promise<Result<string, Error>>));
    /**
     * Allows to set the state manager that will be used by the RP
     * to handle the nonces among the states related to them
     * @param manager A StateManager implementation
     * @returns The next stage of the step builder
     */
    withStateManager(manager: StateManager): OpenIdStepBuilderEndStage;
}
declare class OpenIdStepBuilderEndStage {
    private generalConfiguration;
    private metadata;
    private jwtSignCallback;
    private issuerStateCallback;
    private authzDetailsVerificationCallback;
    private credentialExternalVerification;
    private scopeVerificationFlag;
    private holderMetadata;
    private didResolver;
    private manager;
    private subjectComparison;
    private preAuthCallback;
    constructor(generalConfiguration: RpConfiguration, metadata: AuthServerMetadata, jwtSignCallback: TokenSignCallback, issuerStateCallback: undefined | ((state: string) => Promise<Result<null, Error>>), authzDetailsVerificationCallback: undefined | ((authDetails: AuthorizationDetails) => Promise<Result<null, Error>>), credentialExternalVerification: undefined | CredentialAdditionalVerification, scopeVerificationFlag: boolean, holderMetadata: HolderMetadata, didResolver: Resolver, manager: StateManager, subjectComparison: (firstId: string, secondId: string) => boolean, preAuthCallback?: undefined | ((clientId: string | undefined, preCode: string, pin?: string) => Promise<Result<string, Error>>));
    /**
     * Builds an instance of the RP
     * @returns An instance of OpenIDReliyingParty
     */
    build(): OpenIDReliyingParty;
}
export {};
