import {Resolver} from 'did-resolver';
import {Result} from '../../common/classes/result.js';
import {
  ACCESS_TOKEN_EXPIRATION_TIME,
  AuthServerMetadata,
  AuthorizationDetails,
  C_NONCE_EXPIRATION_TIME,
  HolderMetadata,
  ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME,
  VP_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME,
} from '../../common/index.js';
import {CredentialAdditionalVerification} from '../presentations/types.js';
import {RpConfiguration, TokenSignCallback} from './types.js';
import {StateManager} from '../state/index.js';
import {OpenIDReliyingParty} from './index.js';

/**
 * Step builder that can be used to create an instance of a Reliying Party
 */
export class OpenIdRPStepBuilder {
  private issuerStateCallback:
    | undefined
    | ((state: string) => Promise<Result<null, Error>>) = undefined;
  private authzDetailsVerificationCallback:
    | undefined
    | ((authDetails: AuthorizationDetails) => Promise<Result<null, Error>>) =
    undefined;
  private credentialExternalVerification:
    | undefined
    | CredentialAdditionalVerification = undefined;
  private scopeVerificationFlag = false;
  private subjectComparison: (firstId: string, secondId: string) => boolean = (
    firstId,
    secondId,
  ) => {
    return firstId === secondId;
  };
  private preAuthCallback:
    | undefined
    | ((
        clientId: string | undefined,
        preCode: string,
        pin?: string,
      ) => Promise<Result<string, Error>>) = undefined;
  private generalConfiguration: RpConfiguration = {
    idTokenExpirationTime: ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME,
    vpTokenExpirationTIme: VP_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME,
    cNonceExpirationTime: C_NONCE_EXPIRATION_TIME,
    accessTokenExpirationTime: ACCESS_TOKEN_EXPIRATION_TIME,
  };

  constructor(private metadata: AuthServerMetadata) {}

  /**
   * Allows to overwrite the default expiration time for ID Token Request
   * @param time The new expieration time in ms
   * @returns The same instance of the step builder
   */
  setIdTokenExpirationTime(time: number) {
    this.generalConfiguration.idTokenExpirationTime = time;
    return this;
  }

  /**
   * Allows to overwrite the default expiration time for VP Token Request
   * @param time The new expieration time in ms
   * @returns The same instance of the step builder
   */
  setVpTokenExpirationTime(time: number) {
    this.generalConfiguration.vpTokenExpirationTIme = time;
    return this;
  }

  /**
   * Allows to overwrite the default expiration time for Challenge nonces
   * @param time The new expieration time in seconds
   * @returns The same instance of the step builder
   */
  setCNonceExpirationTime(time: number) {
    this.generalConfiguration.cNonceExpirationTime = time;
    return this;
  }

  /**
   * Allows to overwrite the default expiration time for Access token
   * @param time The new expieration time in ms
   * @returns The same instance of the step builder
   */
  setAccessTokenExpirationTime(time: number) {
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
  withPreAuthCallback(
    callback: (
      clientId: string | undefined,
      preCode: string,
      pin?: string,
    ) => Promise<Result<string, Error>>,
  ) {
    this.preAuthCallback = callback;
    return this;
  }

  /**
   * Allows to establish a callback to handle the "issuer state" parameter of auth request.
   * If not defined, all issuer state will be ignored.
   * @param callback The callback to handle the issuer_state parameter
   * @returns The same instance of the step builder
   */
  withIssuerStateVerification(
    callback: (state: string) => Promise<Result<null, Error>>,
  ) {
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
  withAuthzDetailsVerification(
    callback: (
      authDetails: AuthorizationDetails,
    ) => Promise<Result<null, Error>>,
  ) {
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
  withVpCredentialExternalVerification(
    callback: CredentialAdditionalVerification,
  ) {
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
  withCustomSubjectComparison(
    resolutor: (firstId: string, secondId: string) => boolean,
  ) {
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
  setDefaultHolderMetadata(
    metadata: HolderMetadata,
  ): OpenIdStepBuilderHolderMetadataStage {
    return new OpenIdStepBuilderHolderMetadataStage(
      this.generalConfiguration,
      this.metadata,
      this.issuerStateCallback,
      this.authzDetailsVerificationCallback,
      this.credentialExternalVerification,
      this.scopeVerificationFlag,
      metadata,
      this.subjectComparison,
      this.preAuthCallback,
    );
  }
}

class OpenIdStepBuilderHolderMetadataStage {
  constructor(
    private generalConfiguration: RpConfiguration,
    private metadata: AuthServerMetadata,
    private issuerStateCallback:
      | undefined
      | ((state: string) => Promise<Result<null, Error>>) = undefined,
    private authzDetailsVerificationCallback:
      | undefined
      | ((
          authDetails: AuthorizationDetails,
        ) => Promise<Result<null, Error>>) = undefined,
    private credentialExternalVerification:
      | undefined
      | CredentialAdditionalVerification = undefined,
    private scopeVerificationFlag: boolean,
    private holderMetadata: HolderMetadata,
    private subjectComparison: (firstId: string, secondId: string) => boolean,
    private preAuthCallback:
      | undefined
      | ((
          clientId: string | undefined,
          preCode: string,
          pin?: string,
        ) => Promise<Result<string, Error>>) = undefined,
  ) {}

  /**
   * Allows to set the DID Resolver to use by the RP
   * @param didResolver The DID Resolver to use
   * @returns The next stage of the step builder
   */
  withDidResolver(didResolver: Resolver): OpenIdStepBuilderResolverStage {
    return new OpenIdStepBuilderResolverStage(
      this.generalConfiguration,
      this.metadata,
      this.issuerStateCallback,
      this.authzDetailsVerificationCallback,
      this.credentialExternalVerification,
      this.scopeVerificationFlag,
      this.holderMetadata,
      didResolver,
      this.subjectComparison,
      this.preAuthCallback,
    );
  }
}

class OpenIdStepBuilderResolverStage {
  constructor(
    private generalConfiguration: RpConfiguration,
    private metadata: AuthServerMetadata,
    private issuerStateCallback:
      | undefined
      | ((state: string) => Promise<Result<null, Error>>) = undefined,
    private authzDetailsVerificationCallback:
      | undefined
      | ((
          authDetails: AuthorizationDetails,
        ) => Promise<Result<null, Error>>) = undefined,
    private credentialExternalVerification:
      | undefined
      | CredentialAdditionalVerification = undefined,
    private scopeVerificationFlag: boolean,
    private holderMetadata: HolderMetadata,
    private didResolver: Resolver,
    private subjectComparison: (firstId: string, secondId: string) => boolean,
    private preAuthCallback:
      | undefined
      | ((
          clientId: string | undefined,
          preCode: string,
          pin?: string,
        ) => Promise<Result<string, Error>>) = undefined,
  ) {}

  /**
   * Allows to set the sign callback for all tokens and request that
   * the RP will generate
   * @param jwtSignCallback The callback to use
   * @returns The next stage of the step builder
   */
  withTokenSignCallback(
    jwtSignCallback: TokenSignCallback,
  ): OpenIdStepBuilderSignStage {
    return new OpenIdStepBuilderSignStage(
      this.generalConfiguration,
      this.metadata,
      jwtSignCallback,
      this.issuerStateCallback,
      this.authzDetailsVerificationCallback,
      this.credentialExternalVerification,
      this.scopeVerificationFlag,
      this.holderMetadata,
      this.didResolver,
      this.subjectComparison,
      this.preAuthCallback,
    );
  }
}

class OpenIdStepBuilderSignStage {
  constructor(
    private generalConfiguration: RpConfiguration,
    private metadata: AuthServerMetadata,
    private jwtSignCallback: TokenSignCallback,
    private issuerStateCallback:
      | undefined
      | ((state: string) => Promise<Result<null, Error>>) = undefined,
    private authzDetailsVerificationCallback:
      | undefined
      | ((
          authDetails: AuthorizationDetails,
        ) => Promise<Result<null, Error>>) = undefined,
    private credentialExternalVerification:
      | undefined
      | CredentialAdditionalVerification = undefined,
    private scopeVerificationFlag: boolean,
    private holderMetadata: HolderMetadata,
    private didResolver: Resolver,
    private subjectComparison: (firstId: string, secondId: string) => boolean,
    private preAuthCallback:
      | undefined
      | ((
          clientId: string | undefined,
          preCode: string,
          pin?: string,
        ) => Promise<Result<string, Error>>) = undefined,
  ) {}

  /**
   * Allows to set the state manager that will be used by the RP
   * to handle the nonces among the states related to them
   * @param manager A StateManager implementation
   * @returns The next stage of the step builder
   */
  withStateManager(manager: StateManager): OpenIdStepBuilderEndStage {
    return new OpenIdStepBuilderEndStage(
      this.generalConfiguration,
      this.metadata,
      this.jwtSignCallback,
      this.issuerStateCallback,
      this.authzDetailsVerificationCallback,
      this.credentialExternalVerification,
      this.scopeVerificationFlag,
      this.holderMetadata,
      this.didResolver,
      manager,
      this.subjectComparison,
      this.preAuthCallback,
    );
  }
}

class OpenIdStepBuilderEndStage {
  constructor(
    private generalConfiguration: RpConfiguration,
    private metadata: AuthServerMetadata,
    private jwtSignCallback: TokenSignCallback,
    private issuerStateCallback:
      | undefined
      | ((state: string) => Promise<Result<null, Error>>) = undefined,
    private authzDetailsVerificationCallback:
      | undefined
      | ((
          authDetails: AuthorizationDetails,
        ) => Promise<Result<null, Error>>) = undefined,
    private credentialExternalVerification:
      | undefined
      | CredentialAdditionalVerification = undefined,
    private scopeVerificationFlag: boolean,
    private holderMetadata: HolderMetadata,
    private didResolver: Resolver,
    private manager: StateManager,
    private subjectComparison: (firstId: string, secondId: string) => boolean,
    private preAuthCallback:
      | undefined
      | ((
          clientId: string | undefined,
          preCode: string,
          pin?: string,
        ) => Promise<Result<string, Error>>) = undefined,
  ) {}

  /**
   * Builds an instance of the RP
   * @returns An instance of OpenIDReliyingParty
   */
  build(): OpenIDReliyingParty {
    return new OpenIDReliyingParty(
      this.holderMetadata,
      this.metadata,
      this.didResolver,
      this.jwtSignCallback,
      this.scopeVerificationFlag,
      this.manager,
      this.subjectComparison,
      this.generalConfiguration,
      this.issuerStateCallback,
      this.authzDetailsVerificationCallback,
      this.credentialExternalVerification,
      this.preAuthCallback,
    );
  }
}
