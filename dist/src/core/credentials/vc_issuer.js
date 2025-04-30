import { v4 as uuidv4 } from 'uuid';
import { P, match } from 'ts-pattern';
import moment from 'moment';
import { ControlProof } from '../../common/classes/control_proof.js';
import { CONTEXT_VC_DATA_MODEL_1, CONTEXT_VC_DATA_MODEL_2, C_NONCE_EXPIRATION_TIME, } from '../../common/constants/index.js';
import { W3CDataModel, } from '../../common/formats/index.js';
import { decodeToken, verifyJwtWithExpAndAudience, } from '../../common/utils/jwt.utils.js';
import { VcFormatter } from './formatters.js';
import { InternalNonceError, InvalidCredentialRequest, InvalidDataProvided, InvalidProof, InvalidToken, } from '../../common/classes/index.js';
import { areDidUrlsSameDid } from '../../common/utils/did.utils.js';
import { arraysAreEqual } from '../../common/utils/array.utils.js';
import { NonceManager } from '../nonce/index.js';
/**
 * Component responsible for issuing W3C Verifiable Credentials
 * following the OID4VCI specification.
 *
 * Supports both immediate and deferred issuance flows. Validates requests,
 * signs credentials, and generates the expected credential response objects.
 */
export class W3CVcIssuer {
    metadata;
    didResolver;
    issuerDid;
    signCallback;
    credentialDataManager;
    vcTypesContextRelationship;
    nonceManager;
    /**
     * Initializes the W3CVcIssuer.
     *
     * @param metadata - Metadata of the credential issuer (as defined in OID4VCI).
     * @param didResolver - Resolver used to fetch DID Documents.
     * @param issuerDid - DID of the entity issuing the credentials.
     * @param signCallback - Callback used to sign the VC before returning it.
     * @param stateManager - Manages challenge nonces and issuance-related state.
     * @param credentialDataManager - Provides subject data for the VC or deferred flow logic.
     * @param vcTypesContextRelationship - (Optional) Mapping from VC types to additional context URLs.
     */
    constructor(metadata, didResolver, issuerDid, signCallback, stateManager, credentialDataManager, vcTypesContextRelationship) {
        this.metadata = metadata;
        this.didResolver = didResolver;
        this.issuerDid = issuerDid;
        this.signCallback = signCallback;
        this.credentialDataManager = credentialDataManager;
        this.vcTypesContextRelationship = vcTypesContextRelationship;
        this.nonceManager = new NonceManager(stateManager);
    }
    /**
     * Verifies a JWT Access Token received from a client.
     *
     * This method checks the token's validity (signature, expiration, audience)
     * using the public key of the authorization server. Optionally, it can also
     * apply custom logic through a callback to further validate the token's payload.
     *
     * @param token - JWT Access Token in string format.
     * @param publicKeyJwkAuthServer - Public JWK of the authorization server used to verify the signature.
     * @param tokenVerifyCallback - (Optional) Additional logic to validate the decoded token (e.g. claims).
     * @returns A decoded JWT object if verification succeeds.
     * @throws {InvalidToken} If the token is invalid, expired, has wrong audience, or fails custom validation.
     */
    async verifyAccessToken(token, publicKeyJwkAuthServer, tokenVerifyCallback) {
        await verifyJwtWithExpAndAudience(token, publicKeyJwkAuthServer, this.metadata.credential_issuer);
        const jwt = decodeToken(token);
        if (tokenVerifyCallback) {
            const verificationResult = await tokenVerifyCallback(jwt.header, jwt.payload);
            if (!verificationResult.valid) {
                throw new InvalidToken(`Invalid access token provided${verificationResult.error ? ': ' + verificationResult.error : '.'}`);
            }
        }
        return jwt;
    }
    /**
     * Generates a Credential Response in compliance with the OpenID for Verifiable Credential Issuance (OID4VCI) specification.
     *
     * This method processes a credential request by:
     * - Verifying the associated control proof using a previously issued `c_nonce`.
     * - Validating that the proof signer matches the Access Token subject (when required).
     * - Ensuring the requested credential types are authorized by the Access Token.
     * - Issuing either a Verifiable Credential (VC) or a deferred credential code, depending on the flow.
     *
     * @param accessToken - Decoded Access Token containing authorization to issue the requested VC.
     * @param credentialRequest - The credential request payload received from the client.
     * @param dataModel - Indicates which W3C VC Data Model version to use (v1 or v2).
     * @returns A {@link CredentialResponse} containing either a signed VC or an acceptance token for deferred issuance.
     * @throws {InvalidCredentialRequest | InvalidToken | InvalidProof | InternalNonceError}
     * If the request is malformed, unauthorized, or if the proof or nonce is invalid.
     */
    async generateCredentialResponse(acessToken, credentialRequest, dataModel) {
        this.checkCredentialTypesAndFormat(credentialRequest.types, credentialRequest.format);
        const controlProof = ControlProof.fromJSON(credentialRequest.proof);
        const proofAssociatedClient = controlProof.getAssociatedIdentifier();
        const jwtPayload = acessToken.payload;
        const innerNonce = jwtPayload.nonce;
        const cNonceResult = await this.nonceManager.getChallengeNonce(innerNonce);
        if (cNonceResult.isError()) {
            throw new InvalidProof('Invalid provided nonce for control proof');
        }
        const cNonce = cNonceResult.unwrap();
        if (cNonce.timestamp + cNonce.expirationTime <= Date.now()) {
            await this.nonceManager.deleteNonce(innerNonce);
            throw new InvalidCredentialRequest('Challenge nonce has expired');
        }
        match(cNonce)
            .with({ operationType: { type: 'Verification' } }, _ => {
            throw new InvalidCredentialRequest('Invalid provided nonce');
        })
            .with({
            operationType: {
                type: 'Issuance',
                vcTypes: { type: 'Know', vcTypes: P.select() },
            },
        }, types => {
            if (!areDidUrlsSameDid(proofAssociatedClient, jwtPayload.sub)) {
                throw new InvalidToken('Access Token was issued for a different identifier that the one that sign the proof');
            }
            if (!arraysAreEqual(types, credentialRequest.types)) {
                throw new InvalidCredentialRequest('The provided token does not allow for the issuance of a VC of the specified types');
            }
        })
            .with({ operationType: { type: 'Issuance', vcTypes: { type: 'Uknown' } } }, _ => {
            // Most probably generated from pre-auth flow
        })
            .otherwise(() => {
            throw new InternalNonceError('Unexpected behaviour detected at nonce matching');
        });
        await controlProof.verifyProof(innerNonce, this.metadata.credential_issuer, this.didResolver);
        const credentialSubject = await this.credentialDataManager.resolveCredentialSubject(jwtPayload.sub, proofAssociatedClient);
        const credentialResponse = await this.credentialResponseMatch(credentialRequest.types, credentialSubject, credentialRequest.format, dataModel);
        await this.nonceManager.deleteNonce(innerNonce);
        return credentialResponse;
    }
    async credentialResponseMatch(types, credentialSubject, format, dataModel) {
        const credentialDataOrDeferred = await this.credentialDataManager.getCredentialData(types, credentialSubject);
        return match(credentialDataOrDeferred)
            .with({ type: 'InTime' }, async (data) => this.generateW3CCredential(types, data.schema, credentialSubject, data, format, dataModel))
            .with({ type: 'Deferred' }, data => {
            return {
                acceptance_token: data.deferredCode,
            };
        })
            .exhaustive();
    }
    /**
     * Generates a Verifiable Credential (VC) without requiring an Access Token.
     *
     * This method is typically used in direct issuance flows (e.g., internal tools, testing, or
     * controlled environments) where no authorization layer is applied.
     *
     * It directly triggers the generation of a credential using the provided holder DID, types,
     * format, and data model version. The VC content is obtained through the configured
     * {@link CredentialDataManager}.
     *
     * @param did - The subject identifier (DID) of the future holder of the VC.
     * @param dataModel - Indicates whether the credential should follow the W3C VC Data Model v1 or v2.
     * @param types - The array of types the credential must include.
     * @param format - The serialization format of the credential (e.g., `ldp_vc`, `jwt_vc_json`, etc).
     * @returns A {@link CredentialResponse} containing a signed VC.
     * @throws {InvalidCredentialRequest} If the combination of types and format is not supported.
     */
    async generateVcDirectMode(did, dataModel, types, format) {
        this.checkCredentialTypesAndFormat(types, format);
        return await this.credentialResponseMatch(types, did, format, dataModel);
    }
    // TODO: valorar quitar iss de 'CredentialDataOrDeferred' y homogeneizar comportamiento entre V1 y V2
    // El motivo es que V1 incluye un campo issuanceDate, y además EBSI está obligando a que sea igual al 'iat' del token.
    // Sin embargo, en V2 ese campo no existe. La propusta sería:
    // - En V2, validFrom se asocia con nbf, y iat sería Date.now(). Según esto, en formatDataModel2, iat debería ajustarse a
    //   Date.now() y valorar quitar el nbf o también asignarlo a Date.now(). Notar diferencia entre info de la credencial y del token
    // - En V1, validFrom se asocia con nbf, issued y issuanceDate y iat con Date.now()
    generateCredentialTimeStamps(data) {
        if (data.validUntil && data.expiresInSeconds) {
            throw new InvalidDataProvided('"expiresInSeconds" and "validUntil" can\'t be defined at the same time');
        }
        const issuanceDate = (() => {
            const iss = data.iss ? moment(data.iss, true) : moment();
            if (!iss.isValid()) {
                throw new InvalidDataProvided('Invalid specified date for "iss" parameter');
            }
            return iss;
        })();
        const validFrom = (() => {
            const nbf = data.nbf ? moment(data.nbf, true) : issuanceDate.clone();
            if (!nbf.isValid()) {
                throw new InvalidDataProvided('Invalid specified date for "nbf" parameter');
            }
            if (nbf.isBefore(issuanceDate)) {
                throw new InvalidDataProvided('"validFrom" can not be before "issuanceDate"');
            }
            return nbf;
        })();
        const expirationDate = (() => {
            const exp = (() => {
                if (data.validUntil) {
                    return moment(data.validUntil, true);
                }
                else if (data.expiresInSeconds) {
                    return issuanceDate.clone().add(data.expiresInSeconds, 'seconds');
                }
                else {
                    return undefined;
                }
            })();
            if (exp) {
                if (!exp.isValid()) {
                    throw new InvalidDataProvided('Invalid specified date for "expirationDate" parameter');
                }
                if (exp.isBefore(validFrom)) {
                    throw new InvalidDataProvided('"expirationDate" can not be before "validFrom"');
                }
            }
            return exp;
        })();
        return {
            issuanceDate: issuanceDate.utc().toISOString(),
            validFrom: validFrom.utc().toISOString(),
            expirationDate: expirationDate
                ? expirationDate.utc().toISOString()
                : undefined,
        };
    }
    generateVcId() {
        return `urn:uuid:${uuidv4()}`;
    }
    generateW3CDataForV1(type, schema, subject, vcData) {
        const timestamps = this.generateCredentialTimeStamps(vcData.metadata);
        const vcId = this.generateVcId();
        return {
            '@context': [CONTEXT_VC_DATA_MODEL_1],
            type,
            credentialSchema: schema,
            issuanceDate: timestamps.issuanceDate,
            validFrom: timestamps.validFrom,
            expirationDate: timestamps.expirationDate,
            id: vcId,
            credentialStatus: vcData.status,
            issuer: this.issuerDid,
            issued: timestamps.issuanceDate,
            termsOfUse: vcData.termfOfUse,
            credentialSubject: {
                id: subject,
                ...vcData.data,
            },
        };
    }
    generateW3CDataForV2(type, schema, subject, vcData) {
        const vcId = this.generateVcId();
        const timestamps = this.generateCredentialTimeStamps(vcData.metadata);
        return {
            '@context': [CONTEXT_VC_DATA_MODEL_2],
            type,
            credentialSchema: schema,
            validFrom: timestamps.validFrom,
            validUntil: timestamps.expirationDate,
            id: vcId,
            credentialStatus: vcData.status,
            termsOfUse: vcData.termfOfUse,
            issuer: this.issuerDid,
            credentialSubject: {
                id: subject,
                ...vcData.data,
            },
        };
    }
    extendsVcContext(content) {
        if (!this.vcTypesContextRelationship) {
            return;
        }
        const typesToExtend = Object.keys(this.vcTypesContextRelationship);
        for (const type of content.type) {
            if (typesToExtend.includes(type)) {
                content['@context'].push(this.vcTypesContextRelationship[type]);
            }
        }
    }
    async generateW3CCredential(type, schema, subject, vcData, format, dataModel) {
        const formatter = VcFormatter.fromVcFormat(format, dataModel);
        const content = dataModel === W3CDataModel.V1
            ? this.generateW3CDataForV1(type, schema, subject, vcData)
            : this.generateW3CDataForV2(type, schema, subject, vcData);
        this.extendsVcContext(content);
        const vcPreSign = formatter.formatVc(content);
        const signedVc = await this.signCallback(format, vcPreSign);
        // Generate a new nonce
        const nonce = uuidv4();
        const expirationTime = C_NONCE_EXPIRATION_TIME; // TODO: Make it configurable
        await this.nonceManager.saveNonce(nonce, {
            timestamp: Date.now(),
            sub: subject,
            operationType: {
                type: 'Issuance',
                vcTypes: {
                    type: 'Know',
                    vcTypes: type,
                },
            },
            type: 'ChallengeNonce',
            expirationTime,
        });
        return {
            format: format,
            credential: signedVc,
            c_nonce: nonce,
            c_nonce_expires_in: expirationTime, // TODO: This could be interesting to be configurable
        };
    }
    /**
     * Exchanges a previously issued deferred acceptance token for a Verifiable Credential (VC).
     *
     * This method handles the final step of a deferred issuance flow. The client presents a
     * previously issued `acceptance_token`, and this method either returns the issued credential
     * (if ready), or provides a new `acceptance_token` to poll again later.
     *
     * Internally, it delegates the resolution of credential readiness and subject data to the
     * configured {@link CredentialDataManager}.
     *
     * @param acceptanceToken - The token received in a previous deferred response, identifying the pending VC.
     * @param dataModel - The W3C VC Data Model version to use (`v1` or `v2`).
     * @returns A {@link CredentialResponse} containing either the signed VC or a new deferred token.
     * @throws {InvalidToken} If the provided token is invalid, expired, or unrecognized.
     */
    async exchangeAcceptanceTokenForVc(acceptanceToken, dataModel) {
        const exchangeResult = await this.credentialDataManager.deferredExchange(acceptanceToken);
        if (exchangeResult.isError()) {
            throw new InvalidToken(`Invalid acceptance token: ${exchangeResult.unwrapError().message}`);
        }
        const credentialDataResponse = exchangeResult.unwrap();
        return await match(credentialDataResponse)
            .with({ type: 'InTime' }, async (dataResponse) => this.generateW3CCredential(dataResponse.types, dataResponse.schema, dataResponse.data.id, dataResponse, dataResponse.format, dataModel))
            .with({ type: 'Deferred' }, data => {
            return {
                acceptance_token: data.deferredCode,
            };
        })
            .exhaustive();
    }
    checkCredentialTypesAndFormat(types, format) {
        const typesSet = new Set(types);
        for (const credentialSupported of this.metadata.credentials_supported) {
            const supportedSet = new Set(credentialSupported.types);
            if ([...typesSet].every(item => supportedSet.has(item)) &&
                credentialSupported.format === format) {
                return;
            }
        }
        throw new InvalidCredentialRequest('Unsuported combination of credential types and format');
    }
}
//# sourceMappingURL=vc_issuer.js.map