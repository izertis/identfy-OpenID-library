import { Resolver } from "did-resolver";
import { JWK } from "jose";
import { Jwt } from "jsonwebtoken";
import { W3CDataModel } from "../../common/formats/index.js";
import { CredentialRequest } from "../../common/interfaces/credential_request.interface.js";
import { IssuerMetadata } from "../../common/interfaces/issuer_metadata.interface.js";
import { CredentialResponse } from "../../common/interfaces/credential_response.interface.js";
import * as VcIssuerTypes from "./types.js";
/**
 * W3C credentials issuer in both deferred and In-Time flows
 */
export declare class W3CVcIssuer {
    private metadata;
    private didResolver;
    private issuerDid;
    private signCallback;
    private cNonceRetrieval;
    private getVcSchema;
    private getCredentialData;
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
    constructor(metadata: IssuerMetadata, didResolver: Resolver, issuerDid: string, signCallback: VcIssuerTypes.VcSignCallback, cNonceRetrieval: VcIssuerTypes.ChallengeNonceRetrieval, getVcSchema: VcIssuerTypes.GetCredentialSchema, getCredentialData: VcIssuerTypes.GetCredentialData);
    /**
     * Allows to verify a JWT Access Token in string format
     * @param token The access token
     * @param publicKeyJwkAuthServer The public key that should verify the token
     * @param tokenVerifyCallback A callback that can be used to verify to perform an
     * additional verification of the contents of the token
     * @returns Access token in JWT format
     * @throws If data provided is incorrect
     */
    verifyAccessToken(token: string, publicKeyJwkAuthServer: JWK, tokenVerifyCallback?: VcIssuerTypes.AccessTokenVerifyCallback): Promise<Jwt>;
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
    generateCredentialResponse(acessToken: string | Jwt, credentialRequest: CredentialRequest, dataModel: W3CDataModel, optionalParamaters?: VcIssuerTypes.GenerateCredentialReponseOptionalParams): Promise<CredentialResponse>;
    private generateW3CDataForV1;
    private generateW3CDataForV2;
    private generateW3CCredential;
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
    exchangeAcceptanceTokenForVc(acceptanceToken: string, deferredExchangeCallback: VcIssuerTypes.DeferredExchangeCallback, dataModel: W3CDataModel, optionalParameters?: VcIssuerTypes.BaseOptionalParams): Promise<CredentialResponse>;
    private checkCredentialTypesAndFormat;
}
