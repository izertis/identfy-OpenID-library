import { v4 as uuidv4 } from 'uuid';
import { Resolver } from "did-resolver";
import { JWK } from "jose";
import { Jwt, JwtPayload } from "jsonwebtoken";
import { ControlProof } from "../../common/classes/control_proof.js";
import {
  CONTEXT_VC_DATA_MODEL_1,
  CONTEXT_VC_DATA_MODEL_2,
  C_NONCE_EXPIRATION_TIME
} from "../../common/constants/index.js";
import {
  W3CDataModel,
  W3CVerifiableCredentialFormats
} from "../../common/formats/index.js";
import {
  CredentialRequest
} from "../../common/interfaces/credential_request.interface.js";
import {
  IssuerMetadata
} from "../../common/interfaces/issuer_metadata.interface.js";
import {
  W3CVcSchemaDefinition, W3CVerifiableCredential, W3CVerifiableCredentialV1, W3CVerifiableCredentialV2,
} from "../../common/interfaces/w3c_verifiable_credential.interface";
import {
  decodeToken,
  verifyJwtWithExpAndAudience
} from "../../common/utils/jwt.utils.js";
import { VcFormatter } from './formatters.js';
import {
  CredentialResponse
} from "../../common/interfaces/credential_response.interface.js";
import * as VcIssuerTypes from "./types.js";
import {
  InsufficienteParamaters,
  InternalError,
  InvalidCredentialRequest,
  InvalidToken
} from "../../common/classes/index.js";

/**
 * W3C credentials issuer in both deferred and In-Time flows
 */
export class W3CVcIssuer {
  /**
   * Constructor of the issuer
   * @param metadata Issuer metadata
   * @param didResolver Object that allows to resolve the DIDs found 
   * @param issuerDid The DID of the issuer
   * @param signCallback Callback used to sign the VC generated
   * @param cNonceRetrieval Callback to recover the challenge nonce expected 
   * for a control proof
   * @param getVcSchema Callback to recover the schema associated with a VC
   * @param getCredentialData Callback to recover the subject data to 
   * include in the VC
   * It can also be used to specify if the user should follow the deferred flow
   */
  constructor(
    private metadata: IssuerMetadata,
    private didResolver: Resolver,
    private issuerDid: string,
    private signCallback: VcIssuerTypes.VcSignCallback,
    private cNonceRetrieval: VcIssuerTypes.ChallengeNonceRetrieval,
    private getVcSchema: VcIssuerTypes.GetCredentialSchema,
    private getCredentialData: VcIssuerTypes.GetCredentialData,
  ) { }

  /**
   * Allows to verify a JWT Access Token in string format
   * @param token The access token
   * @param publicKeyJwkAuthServer The public key that should verify the token 
   * @param tokenVerifyCallback A callback that can be used to verify to perform an 
   * additional verification of the contents of the token
   * @returns Access token in JWT format
   * @throws If data provided is incorrect
   */
  async verifyAccessToken(
    token: string,
    publicKeyJwkAuthServer: JWK,
    tokenVerifyCallback?: VcIssuerTypes.AccessTokenVerifyCallback
  ): Promise<Jwt> {
    await verifyJwtWithExpAndAudience(
      token,
      publicKeyJwkAuthServer,
      this.metadata.credential_issuer
    );
    const jwt = decodeToken(token);
    if (tokenVerifyCallback) {
      const verificationResult = await tokenVerifyCallback(
        jwt.header,
        jwt.payload as JwtPayload
      );
      if (!verificationResult.valid) {
        throw new InvalidToken(
          `Invalid access token provided${verificationResult.error ? ": " + verificationResult.error : '.'}`
        );
      }
    }
    return jwt;
  }

  /**
   * Allows to generate a Credential Response in accordance to 
   * the OID4VCI specification
   * @param acessToken The access token needed to perform the operation 
   * @param credentialRequest The credential request sent by an user
   * @param optionalParamaters A set of optional parameters that are only 
   * required if the
   * token is provided in string format and that allows to verify it
   * @returns A credential response with a VC or a deferred code
   * @throws If data provided is incorrect
   */
  async generateCredentialResponse(
    acessToken: string | Jwt,
    credentialRequest: CredentialRequest,
    dataModel: W3CDataModel,
    optionalParamaters?: VcIssuerTypes.GenerateCredentialReponseOptionalParams
  ): Promise<CredentialResponse> {
    if (typeof acessToken === "string") {
      if (!optionalParamaters || !optionalParamaters.tokenVerification) {
        throw new InsufficienteParamaters(
          `"tokenVerification" optional parameter must be set when acessToken is in string format`
        );
      }
      acessToken = await this.verifyAccessToken(
        acessToken,
        optionalParamaters.tokenVerification.publicKeyJwkAuthServer,
        optionalParamaters.tokenVerification.tokenVerifyCallback
      );
    }
    this.checkCredentialTypesAndFormat(credentialRequest.types, credentialRequest.format);
    const controlProof = ControlProof.fromJSON(credentialRequest.proof);
    const proofAssociatedClient = controlProof.getAssociatedIdentifier();
    const jwtPayload = acessToken.payload as JwtPayload;
    if (proofAssociatedClient !== jwtPayload.sub) {
      throw new InvalidToken(
        "Access Token was issued for a different identifier that the one that sign the proof"
      );
    }
    const cNonce = await this.cNonceRetrieval(jwtPayload.sub);
    await controlProof.verifyProof(cNonce,
      this.metadata.credential_issuer,
      this.didResolver
    );
    const credentialDataOrDeferred = await this.getCredentialData(
      credentialRequest.types,
      proofAssociatedClient
    );
    if (credentialDataOrDeferred.deferredCode) {
      return {
        acceptance_token: credentialDataOrDeferred.deferredCode
      }
    } else if (credentialDataOrDeferred.data) {
      return this.generateW3CCredential(
        credentialRequest.types,
        await this.getVcSchema(credentialRequest.types),
        proofAssociatedClient,
        credentialDataOrDeferred.data,
        credentialRequest.format,
        dataModel,
        optionalParamaters
      );
    } else {
      throw new InternalError("No credential data or deferred code received");
    }
  }

  private async generateW3CDataForV1(
    type: string[],
    schema: W3CVcSchemaDefinition[],
    subject: string,
    vcData: Record<string, any>,
    optionalParameters?: VcIssuerTypes.BaseOptionalParams,
  ): Promise<W3CVerifiableCredentialV1> {
    const now = new Date().toISOString();
    const vcId = `vc:${this.metadata.credential_issuer}#${uuidv4()}`;
    return {
      "@context": CONTEXT_VC_DATA_MODEL_1,
      type,
      credentialSchema: schema,
      issuanceDate: now,
      validFrom: now,
      expirationDate: (optionalParameters && optionalParameters.getValidUntil) ?
        await optionalParameters.getValidUntil(
          type
        ) : undefined,
      id: vcId,
      credentialStatus: (optionalParameters && optionalParameters.getCredentialStatus) ?
        await optionalParameters.getCredentialStatus(
          type,
          vcId,
          subject
        ) : undefined,
      issuer: this.issuerDid,
      issued: now,
      credentialSubject: {
        id: subject,
        ...vcData
      }
    }
  }

  private async generateW3CDataForV2(
    type: string[],
    schema: W3CVcSchemaDefinition[],
    subject: string,
    vcData: Record<string, any>,
    optionalParameters?: VcIssuerTypes.BaseOptionalParams,
  ): Promise<W3CVerifiableCredentialV2> {
    const vcId = `vc:${this.metadata.credential_issuer}#${uuidv4()}`;
    return {
      "@context": CONTEXT_VC_DATA_MODEL_2,
      type,
      credentialSchema: schema,
      validFrom: new Date().toISOString(),
      validUntil: (optionalParameters && optionalParameters.getValidUntil) ?
        await optionalParameters.getValidUntil(
          type
        ) : undefined,
      id: vcId,
      credentialStatus: (optionalParameters && optionalParameters.getCredentialStatus) ?
        await optionalParameters.getCredentialStatus(
          type,
          vcId,
          subject
        ) : undefined,
      issuer: this.issuerDid,
      credentialSubject: {
        id: subject,
        ...vcData
      }
    }
  }

  private async generateW3CCredential(
    type: string[],
    schema: W3CVcSchemaDefinition[],
    subject: string,
    vcData: Record<string, any>,
    format: W3CVerifiableCredentialFormats,
    dataModel: W3CDataModel,
    optionalParameters?: VcIssuerTypes.BaseOptionalParams,
  ): Promise<CredentialResponse> {
    const formatter = VcFormatter.fromVcFormat(format, dataModel);
    const content: W3CVerifiableCredential = dataModel === W3CDataModel.V1 ?
      await this.generateW3CDataForV1(type, schema, subject, vcData, optionalParameters) :
      await this.generateW3CDataForV2(type, schema, subject, vcData, optionalParameters)
    const vcPreSign = formatter.formatVc(content);
    const signedVc = await this.signCallback(format, vcPreSign);
    return {
      format: format,
      credential: signedVc,
      c_nonce: (optionalParameters &&
        optionalParameters.cNonceToEmploy) ? optionalParameters.cNonceToEmploy : uuidv4(),
      c_nonce_expires_in: (optionalParameters &&
        optionalParameters.cNonceExp) ? optionalParameters.cNonceExp : C_NONCE_EXPIRATION_TIME
    }
  }

  /**
   * Allows to exchange a deferred code for a VC
   * @param acceptanceToken The deferred code sent by the issuer in a 
   * previous instance
   * @param deferredExchangeCallback A callback to verify the deferred code
   * @param optionalParameters A set of optional parameters that allow to 
   * specify certain 
   * data of the VC generated
   * @returns A credential response with the VC generated or a new 
   * (or the same) deferred code
   */
  async exchangeAcceptanceTokenForVc(
    acceptanceToken: string,
    deferredExchangeCallback: VcIssuerTypes.DeferredExchangeCallback,
    dataModel: W3CDataModel,
    optionalParameters?: VcIssuerTypes.BaseOptionalParams,
  ): Promise<CredentialResponse> {
    const exchangeResult = await deferredExchangeCallback(acceptanceToken);
    if ("error" in exchangeResult) {
      throw new InvalidToken(`Invalid acceptance token: ${exchangeResult.error}`);
    }
    if (exchangeResult.deferredCode) {
      return { acceptance_token: exchangeResult.deferredCode };
    }
    return this.generateW3CCredential(
      exchangeResult.types,
      await this.getVcSchema(exchangeResult.types),
      exchangeResult.data?.id!,
      exchangeResult.data!,
      exchangeResult.format,
      dataModel,
      optionalParameters
    );
  }

  private checkCredentialTypesAndFormat(
    types: string[],
    format: W3CVerifiableCredentialFormats
  ) {
    const typesSet = new Set(types);
    for (const credentialSupported of this.metadata.credentials_supported) {
      const supportedSet = new Set(credentialSupported.types);
      if ([...typesSet].every((item) => supportedSet.has(item)) && credentialSupported.format === format) {
        return;
      }
    }
    throw new InvalidCredentialRequest(
      "Unsuported combination of credential types and format"
    );
  }
}
