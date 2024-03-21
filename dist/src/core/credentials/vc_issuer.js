var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { v4 as uuidv4 } from 'uuid';
import { ControlProof } from "../../common/classes/control_proof.js";
import { CONTEXT_VC_DATA_MODEL_1, CONTEXT_VC_DATA_MODEL_2, C_NONCE_EXPIRATION_TIME } from "../../common/constants/index.js";
import { W3CDataModel } from "../../common/formats/index.js";
import { decodeToken, verifyJwtWithExpAndAudience } from "../../common/utils/jwt.utils.js";
import { VcFormatter } from './formatters.js';
import { InsufficienteParamaters, InternalError, InvalidCredentialRequest, InvalidToken } from "../../common/classes/index.js";
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
    constructor(metadata, didResolver, issuerDid, signCallback, cNonceRetrieval, getVcSchema, getCredentialData) {
        this.metadata = metadata;
        this.didResolver = didResolver;
        this.issuerDid = issuerDid;
        this.signCallback = signCallback;
        this.cNonceRetrieval = cNonceRetrieval;
        this.getVcSchema = getVcSchema;
        this.getCredentialData = getCredentialData;
    }
    /**
     * Allows to verify a JWT Access Token in string format
     * @param token The access token
     * @param publicKeyJwkAuthServer The public key that should verify the token
     * @param tokenVerifyCallback A callback that can be used to verify to perform an
     * additional verification of the contents of the token
     * @returns Access token in JWT format
     * @throws If data provided is incorrect
     */
    verifyAccessToken(token, publicKeyJwkAuthServer, tokenVerifyCallback) {
        return __awaiter(this, void 0, void 0, function* () {
            yield verifyJwtWithExpAndAudience(token, publicKeyJwkAuthServer, this.metadata.credential_issuer);
            const jwt = decodeToken(token);
            if (tokenVerifyCallback) {
                const verificationResult = yield tokenVerifyCallback(jwt.header, jwt.payload);
                if (!verificationResult.valid) {
                    throw new InvalidToken(`Invalid access token provided${verificationResult.error ? ": " + verificationResult.error : '.'}`);
                }
            }
            return jwt;
        });
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
    generateCredentialResponse(acessToken, credentialRequest, dataModel, optionalParamaters) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof acessToken === "string") {
                if (!optionalParamaters || !optionalParamaters.tokenVerification) {
                    throw new InsufficienteParamaters(`"tokenVerification" optional parameter must be set when acessToken is in string format`);
                }
                acessToken = yield this.verifyAccessToken(acessToken, optionalParamaters.tokenVerification.publicKeyJwkAuthServer, optionalParamaters.tokenVerification.tokenVerifyCallback);
            }
            this.checkCredentialTypesAndFormat(credentialRequest.types, credentialRequest.format);
            const controlProof = ControlProof.fromJSON(credentialRequest.proof);
            const proofAssociatedClient = controlProof.getAssociatedIdentifier();
            const jwtPayload = acessToken.payload;
            if (proofAssociatedClient !== jwtPayload.sub) {
                throw new InvalidToken("Access Token was issued for a different identifier that the one that sign the proof");
            }
            const cNonce = yield this.cNonceRetrieval(jwtPayload.sub);
            yield controlProof.verifyProof(cNonce, this.metadata.credential_issuer, this.didResolver);
            const credentialDataOrDeferred = yield this.getCredentialData(credentialRequest.types, proofAssociatedClient);
            if (credentialDataOrDeferred.deferredCode) {
                return {
                    acceptance_token: credentialDataOrDeferred.deferredCode
                };
            }
            else if (credentialDataOrDeferred.data) {
                return this.generateW3CCredential(credentialRequest.types, yield this.getVcSchema(credentialRequest.types), proofAssociatedClient, credentialDataOrDeferred.data, credentialRequest.format, dataModel, optionalParamaters);
            }
            else {
                throw new InternalError("No credential data or deferred code received");
            }
        });
    }
    generateW3CDataForV1(type, schema, subject, vcData, optionalParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            const now = new Date().toISOString();
            const vcId = `vc:${this.metadata.credential_issuer}#${uuidv4()}`;
            return {
                "@context": CONTEXT_VC_DATA_MODEL_1,
                type,
                credentialSchema: schema,
                issuanceDate: now,
                validFrom: now,
                expirationDate: (optionalParameters && optionalParameters.getValidUntil) ?
                    yield optionalParameters.getValidUntil(type) : undefined,
                id: vcId,
                credentialStatus: (optionalParameters && optionalParameters.getCredentialStatus) ?
                    yield optionalParameters.getCredentialStatus(type, vcId, subject) : undefined,
                issuer: this.issuerDid,
                issued: now,
                credentialSubject: Object.assign({ id: subject }, vcData)
            };
        });
    }
    generateW3CDataForV2(type, schema, subject, vcData, optionalParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            const vcId = `vc:${this.metadata.credential_issuer}#${uuidv4()}`;
            return {
                "@context": CONTEXT_VC_DATA_MODEL_2,
                type,
                credentialSchema: schema,
                validFrom: new Date().toISOString(),
                validUntil: (optionalParameters && optionalParameters.getValidUntil) ?
                    yield optionalParameters.getValidUntil(type) : undefined,
                id: vcId,
                credentialStatus: (optionalParameters && optionalParameters.getCredentialStatus) ?
                    yield optionalParameters.getCredentialStatus(type, vcId, subject) : undefined,
                issuer: this.issuerDid,
                credentialSubject: Object.assign({ id: subject }, vcData)
            };
        });
    }
    generateW3CCredential(type, schema, subject, vcData, format, dataModel, optionalParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            const formatter = VcFormatter.fromVcFormat(format, dataModel);
            const content = dataModel === W3CDataModel.V1 ?
                yield this.generateW3CDataForV1(type, schema, subject, vcData, optionalParameters) :
                yield this.generateW3CDataForV2(type, schema, subject, vcData, optionalParameters);
            const vcPreSign = formatter.formatVc(content);
            const signedVc = yield this.signCallback(format, vcPreSign);
            return {
                format: format,
                credential: signedVc,
                c_nonce: (optionalParameters &&
                    optionalParameters.cNonceToEmploy) ? optionalParameters.cNonceToEmploy : uuidv4(),
                c_nonce_expires_in: (optionalParameters &&
                    optionalParameters.cNonceExp) ? optionalParameters.cNonceExp : C_NONCE_EXPIRATION_TIME
            };
        });
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
    exchangeAcceptanceTokenForVc(acceptanceToken, deferredExchangeCallback, dataModel, optionalParameters) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const exchangeResult = yield deferredExchangeCallback(acceptanceToken);
            if ("error" in exchangeResult) {
                throw new InvalidToken(`Invalid acceptance token: ${exchangeResult.error}`);
            }
            if (exchangeResult.deferredCode) {
                return { acceptance_token: exchangeResult.deferredCode };
            }
            return this.generateW3CCredential(exchangeResult.types, yield this.getVcSchema(exchangeResult.types), (_a = exchangeResult.data) === null || _a === void 0 ? void 0 : _a.id, exchangeResult.data, exchangeResult.format, dataModel, optionalParameters);
        });
    }
    checkCredentialTypesAndFormat(types, format) {
        const typesSet = new Set(types);
        for (const credentialSupported of this.metadata.credentials_supported) {
            const supportedSet = new Set(credentialSupported.types);
            if ([...typesSet].every((item) => supportedSet.has(item)) && credentialSupported.format === format) {
                return;
            }
        }
        throw new InvalidCredentialRequest("Unsuported combination of credential types and format");
    }
}
