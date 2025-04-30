import { ACCESS_TOKEN_EXPIRATION_TIME, C_NONCE_EXPIRATION_TIME, ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME, VP_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME, } from '../../common/index.js';
import { OpenIDReliyingParty } from './index.js';
/**
 * Step builder that can be used to create an instance of a Reliying Party
 */
export class OpenIdRPStepBuilder {
    metadata;
    issuerStateCallback = undefined;
    authzDetailsVerificationCallback = undefined;
    credentialExternalVerification = undefined;
    scopeVerificationFlag = false;
    subjectComparison = (firstId, secondId) => {
        return firstId === secondId;
    };
    preAuthCallback = undefined;
    generalConfiguration = {
        idTokenExpirationTime: ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME,
        vpTokenExpirationTIme: VP_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME,
        cNonceExpirationTime: C_NONCE_EXPIRATION_TIME,
        accessTokenExpirationTime: ACCESS_TOKEN_EXPIRATION_TIME,
    };
    constructor(metadata) {
        this.metadata = metadata;
    }
    /**
     * Allows to overwrite the default expiration time for ID Token Request
     * @param time The new expieration time in ms
     * @returns The same instance of the step builder
     */
    setIdTokenExpirationTime(time) {
        this.generalConfiguration.idTokenExpirationTime = time;
        return this;
    }
    /**
     * Allows to overwrite the default expiration time for VP Token Request
     * @param time The new expieration time in ms
     * @returns The same instance of the step builder
     */
    setVpTokenExpirationTime(time) {
        this.generalConfiguration.vpTokenExpirationTIme = time;
        return this;
    }
    /**
     * Allows to overwrite the default expiration time for Challenge nonces
     * @param time The new expieration time in seconds
     * @returns The same instance of the step builder
     */
    setCNonceExpirationTime(time) {
        this.generalConfiguration.cNonceExpirationTime = time;
        return this;
    }
    /**
     * Allows to overwrite the default expiration time for Access token
     * @param time The new expieration time in ms
     * @returns The same instance of the step builder
     */
    setAccessTokenExpirationTime(time) {
        this.generalConfiguration.accessTokenExpirationTime = time;
        return this;
    }
    /**
     * Allows to establish a callback to handle token request that use the pre-auth
     * grant type. If not defined, all requests of this type will be rejected
     * @param callback The callback to handle the Pre-Auth Code. A "result" objet with the
     * real clientId of the user is expected
     * @returns The same instance of the step builder
     */
    withPreAuthCallback(callback) {
        this.preAuthCallback = callback;
        return this;
    }
    /**
     * Allows to establish a callback to handle the "issuer state" parameter of auth request.
     * If not defined, all issuer state will be ignored.
     * @param callback The callback to handle the issuer_state parameter
     * @returns The same instance of the step builder
     */
    withIssuerStateVerification(callback) {
        this.issuerStateCallback = callback;
        return this;
    }
    /**
     * Allows to establish a callback to perfom a specific verification of the Authz details
     * of Authz Request. If not defined, only a basic verification will be perfomed, in which the
     * validity of the contentes of the details are not analyzed.
     * @param callback The callback to handle the authz details
     * @returns The same instance of the step builder
     */
    withAuthzDetailsVerification(callback) {
        this.authzDetailsVerificationCallback = callback;
        return this;
    }
    /**
     * Allows to set a flag to perfome scope verification against authz server metadata
     * @returns The same instance of the step builder
     */
    withScopeVerification() {
        this.scopeVerificationFlag = true;
        return this;
    }
    /**
     * Allows to set a callback to vefify the extracted data of the VCs in a VP
     * according to the presentation definition
     * @param callback The callback that handle the verification
     * @returns The same instance of the step builder
     */
    withVpCredentialExternalVerification(callback) {
        this.credentialExternalVerification = callback;
        return this;
    }
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
    withCustomSubjectComparison(resolutor) {
        this.subjectComparison = resolutor;
        return this;
    }
    /**
     * Allows to specify the default metadata for all holder that establish contact with the
     * authz server. The specified emtadata will repace any omitted parameter by the holder.
     * This method also ends the first stage of the step builder.
     * @param metadata The metadata to use
     * @returns The next stage of the step builder, focused on the DID Resolvers
     */
    setDefaultHolderMetadata(metadata) {
        return new OpenIdStepBuilderHolderMetadataStage(this.generalConfiguration, this.metadata, this.issuerStateCallback, this.authzDetailsVerificationCallback, this.credentialExternalVerification, this.scopeVerificationFlag, metadata, this.subjectComparison, this.preAuthCallback);
    }
}
class OpenIdStepBuilderHolderMetadataStage {
    generalConfiguration;
    metadata;
    issuerStateCallback;
    authzDetailsVerificationCallback;
    credentialExternalVerification;
    scopeVerificationFlag;
    holderMetadata;
    subjectComparison;
    preAuthCallback;
    constructor(generalConfiguration, metadata, issuerStateCallback = undefined, authzDetailsVerificationCallback = undefined, credentialExternalVerification = undefined, scopeVerificationFlag, holderMetadata, subjectComparison, preAuthCallback = undefined) {
        this.generalConfiguration = generalConfiguration;
        this.metadata = metadata;
        this.issuerStateCallback = issuerStateCallback;
        this.authzDetailsVerificationCallback = authzDetailsVerificationCallback;
        this.credentialExternalVerification = credentialExternalVerification;
        this.scopeVerificationFlag = scopeVerificationFlag;
        this.holderMetadata = holderMetadata;
        this.subjectComparison = subjectComparison;
        this.preAuthCallback = preAuthCallback;
    }
    /**
     * Allows to set the DID Resolver to use by the RP
     * @param didResolver The DID Resolver to use
     * @returns The next stage of the step builder
     */
    withDidResolver(didResolver) {
        return new OpenIdStepBuilderResolverStage(this.generalConfiguration, this.metadata, this.issuerStateCallback, this.authzDetailsVerificationCallback, this.credentialExternalVerification, this.scopeVerificationFlag, this.holderMetadata, didResolver, this.subjectComparison, this.preAuthCallback);
    }
}
class OpenIdStepBuilderResolverStage {
    generalConfiguration;
    metadata;
    issuerStateCallback;
    authzDetailsVerificationCallback;
    credentialExternalVerification;
    scopeVerificationFlag;
    holderMetadata;
    didResolver;
    subjectComparison;
    preAuthCallback;
    constructor(generalConfiguration, metadata, issuerStateCallback = undefined, authzDetailsVerificationCallback = undefined, credentialExternalVerification = undefined, scopeVerificationFlag, holderMetadata, didResolver, subjectComparison, preAuthCallback = undefined) {
        this.generalConfiguration = generalConfiguration;
        this.metadata = metadata;
        this.issuerStateCallback = issuerStateCallback;
        this.authzDetailsVerificationCallback = authzDetailsVerificationCallback;
        this.credentialExternalVerification = credentialExternalVerification;
        this.scopeVerificationFlag = scopeVerificationFlag;
        this.holderMetadata = holderMetadata;
        this.didResolver = didResolver;
        this.subjectComparison = subjectComparison;
        this.preAuthCallback = preAuthCallback;
    }
    /**
     * Allows to set the sign callback for all tokens and request that
     * the RP will generate
     * @param jwtSignCallback The callback to use
     * @returns The next stage of the step builder
     */
    withTokenSignCallback(jwtSignCallback) {
        return new OpenIdStepBuilderSignStage(this.generalConfiguration, this.metadata, jwtSignCallback, this.issuerStateCallback, this.authzDetailsVerificationCallback, this.credentialExternalVerification, this.scopeVerificationFlag, this.holderMetadata, this.didResolver, this.subjectComparison, this.preAuthCallback);
    }
}
class OpenIdStepBuilderSignStage {
    generalConfiguration;
    metadata;
    jwtSignCallback;
    issuerStateCallback;
    authzDetailsVerificationCallback;
    credentialExternalVerification;
    scopeVerificationFlag;
    holderMetadata;
    didResolver;
    subjectComparison;
    preAuthCallback;
    constructor(generalConfiguration, metadata, jwtSignCallback, issuerStateCallback = undefined, authzDetailsVerificationCallback = undefined, credentialExternalVerification = undefined, scopeVerificationFlag, holderMetadata, didResolver, subjectComparison, preAuthCallback = undefined) {
        this.generalConfiguration = generalConfiguration;
        this.metadata = metadata;
        this.jwtSignCallback = jwtSignCallback;
        this.issuerStateCallback = issuerStateCallback;
        this.authzDetailsVerificationCallback = authzDetailsVerificationCallback;
        this.credentialExternalVerification = credentialExternalVerification;
        this.scopeVerificationFlag = scopeVerificationFlag;
        this.holderMetadata = holderMetadata;
        this.didResolver = didResolver;
        this.subjectComparison = subjectComparison;
        this.preAuthCallback = preAuthCallback;
    }
    /**
     * Allows to set the state manager that will be used by the RP
     * to handle the nonces among the states related to them
     * @param manager A StateManager implementation
     * @returns The next stage of the step builder
     */
    withStateManager(manager) {
        return new OpenIdStepBuilderEndStage(this.generalConfiguration, this.metadata, this.jwtSignCallback, this.issuerStateCallback, this.authzDetailsVerificationCallback, this.credentialExternalVerification, this.scopeVerificationFlag, this.holderMetadata, this.didResolver, manager, this.subjectComparison, this.preAuthCallback);
    }
}
class OpenIdStepBuilderEndStage {
    generalConfiguration;
    metadata;
    jwtSignCallback;
    issuerStateCallback;
    authzDetailsVerificationCallback;
    credentialExternalVerification;
    scopeVerificationFlag;
    holderMetadata;
    didResolver;
    manager;
    subjectComparison;
    preAuthCallback;
    constructor(generalConfiguration, metadata, jwtSignCallback, issuerStateCallback = undefined, authzDetailsVerificationCallback = undefined, credentialExternalVerification = undefined, scopeVerificationFlag, holderMetadata, didResolver, manager, subjectComparison, preAuthCallback = undefined) {
        this.generalConfiguration = generalConfiguration;
        this.metadata = metadata;
        this.jwtSignCallback = jwtSignCallback;
        this.issuerStateCallback = issuerStateCallback;
        this.authzDetailsVerificationCallback = authzDetailsVerificationCallback;
        this.credentialExternalVerification = credentialExternalVerification;
        this.scopeVerificationFlag = scopeVerificationFlag;
        this.holderMetadata = holderMetadata;
        this.didResolver = didResolver;
        this.manager = manager;
        this.subjectComparison = subjectComparison;
        this.preAuthCallback = preAuthCallback;
    }
    /**
     * Builds an instance of the RP
     * @returns An instance of OpenIDReliyingParty
     */
    build() {
        return new OpenIDReliyingParty(this.holderMetadata, this.metadata, this.didResolver, this.jwtSignCallback, this.scopeVerificationFlag, this.manager, this.subjectComparison, this.generalConfiguration, this.issuerStateCallback, this.authzDetailsVerificationCallback, this.credentialExternalVerification, this.preAuthCallback);
    }
}
//# sourceMappingURL=builder.js.map