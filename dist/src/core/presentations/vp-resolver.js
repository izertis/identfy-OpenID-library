var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import jsonpath from "jsonpath";
import fetch from 'node-fetch';
import { importJWK, jwtVerify } from "jose";
import { ajv } from "./validator.js";
import { W3CDataModel } from "../../common/formats/index.js";
import { CONTEXT_VC_DATA_MODEL_1, CONTEXT_VC_DATA_MODEL_2, W3C_VP_TYPE } from "../../common/constants/index.js";
import { decodeToken, didFromDidUrl, getAssertionMethodJWKKeys, getAuthentificationJWKKeys, obtainDid } from "../../common/utils/index.js";
import { InternalError, InvalidRequest } from "../../common/classes/error/index.js";
/**
 * Component specialized in the verification of verifiable
 * submissions, for which it requires the original definition
 * and the submission delivered together with the VP.
 */
export class VpResolver {
    /**
     * Main constructor of this class
     * @param didResolver The DID Resolver to employ
     * @param audience The expected audience in the tokens that will be processed
     * @param externalValidation Callback that will be used to request external
     * verification of any detected VC. This verification should focus on
     * validating issues related to the trust framework and the use case.
     * @param nonceValidation Callback the nonces specified in any JWT VP
     * @param vcSignatureVerification Flag indicating whether the signatures of the VCs
     * included in the VP should be verified. To that regard, the DID Resolver provided must
     * be able to generate the needed DID Documents
     */
    constructor(didResolver, audience, externalValidation, nonceValidation, vcSignatureVerification = false) {
        this.didResolver = didResolver;
        this.audience = audience;
        this.externalValidation = externalValidation;
        this.nonceValidation = nonceValidation;
        this.vcSignatureVerification = vcSignatureVerification;
        this.jwtCache = {};
    }
    /**
     * Verify a Verifiable Presentation
     * @param vp Any data structure in which the VP is located
     * @param definition The definition of the presentation to be
     * used to verify the PV
     * @param submission The presentation submission submitted with the VP
     * @returns Data extracted from the credentials contained
     * in the VP as indicated in the definition provided.
     */
    verifyPresentation(vp, definition, submission) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            try {
                if (definition.id !== submission.definition_id) {
                    throw new InvalidRequest("The submission definition ID is incorrect");
                }
                if (submission.descriptor_map.length !== definition.input_descriptors.length) {
                    throw new InvalidRequest("The descriptor map length does not coincide with the input descriptors one");
                }
                const idsAlreadyUsed = new Set();
                const descriptorClaimsMap = {};
                for (const descriptor of submission.descriptor_map) {
                    if (idsAlreadyUsed.has(descriptor.id)) {
                        throw new InvalidRequest("Can't be two descriptors with the same ID");
                    }
                    const inputDescriptor = this.findDefinitionInputDescriptor(definition, descriptor.id);
                    const rootFormats = definition.format;
                    const format = (_a = inputDescriptor.format) !== null && _a !== void 0 ? _a : rootFormats;
                    const vc = yield this.extractCredentialFromVp(vp, descriptor, rootFormats, format);
                    const claimData = yield this.resolveInputDescriptor(inputDescriptor, vc);
                    descriptorClaimsMap[inputDescriptor.id] = claimData;
                    idsAlreadyUsed.add(inputDescriptor.id);
                }
                this.jwtCache = {};
                const result = {
                    claimsData: descriptorClaimsMap,
                    holderDid: this.vpHolder
                };
                this.vpHolder = undefined;
                return result;
            }
            catch (error) {
                this.jwtCache = {};
                this.vpHolder = undefined;
                throw error;
            }
        });
    }
    deserializeJwtVc(data, validAlgs, descriptorId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof data !== "string") {
                throw new InvalidRequest("JWT Token must be in string format");
            }
            const cacheData = this.jwtCache[data];
            if (cacheData && cacheData.type == "vc") {
                return { data: cacheData.data, jwa: cacheData.alg };
            }
            const { header, payload } = decodeToken(data);
            if (!header.kid) {
                throw new InvalidRequest(`Descriptor "${descriptorId}" JWT VC must contains a 'kid' parameter`);
            }
            if (!validAlgs.includes(header.alg)) {
                throw new InvalidRequest(`Descriptor "${descriptorId}" JWT VC unssuported JWA: ${header.alg}`);
            }
            if (!("vc" in payload)) {
                throw new InvalidRequest(`Descriptor ${descriptorId} is not a JWT VC`);
            }
            const vc = payload.vc;
            const dataModelVersion = this.checkVcDataModel(vc);
            this.verifyVcDates(vc, dataModelVersion, descriptorId);
            if (!vc.credentialSubject.id) {
                throw new InvalidRequest(`Credential Subject not defined`);
            }
            const vcSubject = vc.credentialSubject.id;
            const vcSubjectDid = didFromDidUrl(vcSubject);
            if (vcSubjectDid) {
                if (!this.vpHolder) {
                    throw new InvalidRequest("A VC has been detected prior to any VP");
                }
                if (this.vpHolder !== vcSubjectDid) {
                    throw new InvalidRequest("Credential subject ID and VP Holder mismatch");
                }
            }
            let publicKey;
            if (this.vcSignatureVerification) {
                const didResolution = yield this.didResolver.resolve(vc.issuer);
                if (didResolution.didResolutionMetadata.error) {
                    throw new InvalidRequest(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error}: ${didResolution.didResolutionMetadata.message}`);
                }
                const didDocument = didResolution.didDocument;
                const jwk = getAssertionMethodJWKKeys(didDocument, header.kid);
                publicKey = yield importJWK(jwk);
                try {
                    yield jwtVerify(data, publicKey, { clockTolerance: 5 });
                }
                catch (error) {
                    throw new InvalidRequest(`Descriptor "${descriptorId}" JWT verification failed`);
                }
            }
            // Verify VC Schema
            if (vc.credentialSchema) {
                const schemaArray = Array.isArray(vc.credentialSchema) ?
                    vc.credentialSchema :
                    [vc.credentialSchema];
                for (const W3CSchema of schemaArray) {
                    const schema = yield this.getSchema(W3CSchema);
                    const validateFunction = yield ajv.compileAsync(schema);
                    const validationResult = validateFunction(vc);
                    if (!validationResult) {
                        throw new InvalidRequest("VC does not validate against its own schema specification");
                    }
                }
            }
            const verificationResult = yield this.externalValidation(vc, dataModelVersion, publicKey);
            if (!verificationResult.valid) {
                throw new InvalidRequest(verificationResult.error);
            }
            this.jwtCache[data] = {
                data: payload,
                alg: header.alg,
                type: "vc"
            };
            return {
                data: payload,
                jwa: header.alg
            };
        });
    }
    getSchema(schema) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const response = yield fetch(schema.id);
                return yield response.json();
            }
            catch (e) {
                throw new InvalidRequest(`Can't recover credential schema: ${e}`);
            }
        });
    }
    decodeAndParse(format, data, validAlgs, descriptorId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (checkIfLdFormat(format)) {
                throw new InternalError("LD Format are not supported right now");
            }
            switch (format) {
                case "jwt_vc":
                case "jwt_vc_json":
                    return Object.assign({}, yield this.deserializeJwtVc(data, validAlgs, descriptorId));
                case "jwt_vp":
                case "jwt_vp_json":
                    return Object.assign({}, yield this.deserializeJwtVp(data, validAlgs, descriptorId));
                case "jwt_vc_json-ld":
                case "ldp_vc":
                case "ldp_vp":
                    throw new InternalError("LD formats are not supported right now");
            }
        });
    }
    deserializeJwtVp(data, validAlgs, descriptorId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof data !== "string") {
                throw new InvalidRequest("A JWT VP must be in string format");
            }
            const cacheData = this.jwtCache[data];
            if (cacheData && cacheData.type == "vp") {
                return { data: cacheData.data, jwa: cacheData.alg };
            }
            const { header, payload } = decodeToken(data);
            if (!header.kid) {
                throw new InvalidRequest(`Descriptor "${descriptorId}" JWT VP must contains a 'kid' parameter`);
            }
            if (!validAlgs.includes(header.alg)) {
                throw new InvalidRequest(`Descriptor "${descriptorId}" JWT VP unssuported JWA: ${header.alg}`);
            }
            const jwtPayload = payload;
            if (!jwtPayload.vp) {
                throw new InvalidRequest(`Descriptor ${descriptorId} is not a JWT VP`);
            }
            const vp = payload.vp;
            if (!vp.type.includes(W3C_VP_TYPE)) {
                throw new InvalidRequest(`Descriptor ${descriptorId} JWT VP must be of type "${W3C_VP_TYPE}"`);
            }
            if (jwtPayload.aud !== this.audience) {
                throw new InvalidRequest("Invalid audience for VP Token");
            }
            const holderDidUrl = obtainDid(header.kid, vp.holder);
            const didResolution = yield this.didResolver.resolve(holderDidUrl);
            if (didResolution.didResolutionMetadata.error) {
                throw new InvalidRequest(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error}: ${didResolution.didResolutionMetadata.message}`);
            }
            const didDocument = didResolution.didDocument;
            const holderDid = didDocument.id;
            const jwk = getAuthentificationJWKKeys(didDocument, header.kid);
            const publicKey = yield importJWK(jwk);
            yield jwtVerify(data, publicKey, { clockTolerance: 5 });
            const nonceVerification = yield this.nonceValidation(holderDidUrl, jwtPayload.nonce);
            if (!nonceVerification.valid) {
                throw new InvalidRequest(`Descriptor ${descriptorId} invalid nonce specified${nonceVerification.error ?
                    `: ${nonceVerification.error}`
                    : '.'}`);
            }
            this.vpHolder = holderDid;
            this.jwtCache[data] = {
                data: payload,
                alg: header.alg,
                type: "vp"
            };
            return {
                data: payload,
                jwa: header.alg
            };
        });
    }
    verifyVcDates(vc, dataModel, descriptorId) {
        const now = Date.now();
        if (vc.validFrom) {
            const validFrom = Date.parse(vc.validFrom);
            if (validFrom > now) {
                throw new InvalidRequest(`${descriptorId} is not yet valid`);
            }
        }
        switch (dataModel) {
            case W3CDataModel.V1:
                const vcV1 = vc;
                if (!vcV1.issuanceDate) {
                    throw new InvalidRequest("A W3C VC for data model V1 Must contain an issuanceDate parameter");
                }
                const issuanceDate = Date.parse(vcV1.issuanceDate);
                if (now < issuanceDate) {
                    throw new InvalidRequest(`${descriptorId} invalid issuance date`);
                }
                if (vcV1.expirationDate) {
                    const expirationDate = Date.parse(vcV1.expirationDate);
                    if (now >= expirationDate) {
                        throw new InvalidRequest(`${descriptorId} is expired`);
                    }
                }
                break;
            case W3CDataModel.V2:
                const vcV2 = vc;
                if (vcV2.validUntil) {
                    const validUntil = Date.parse(vcV2.validUntil);
                    if (validUntil <= now) {
                        throw new InvalidRequest(`${descriptorId} is expired`);
                    }
                }
                break;
        }
    }
    checkVcDataModel(vc) {
        if (CONTEXT_VC_DATA_MODEL_1.every((x) => vc["@context"].includes(x))) {
            return W3CDataModel.V1;
        }
        if (CONTEXT_VC_DATA_MODEL_2.every((x) => vc["@context"].includes(x))) {
            return W3CDataModel.V2;
        }
        throw new InvalidRequest("Invalid @¢ontext specified");
    }
    checkFormatValidity(expectedFormats, currentFormat) {
        const formatData = expectedFormats[currentFormat];
        if (!formatData) {
            throw new InvalidRequest("Unexpected format detected");
        }
        if (("proof_type") in formatData) {
            throw new InternalError("JLD not supported right now");
        }
        if (("alg") in formatData) {
            return formatData.alg;
        }
        throw new InvalidRequest("Unrecognized format detected");
    }
    extractCredentialFromVp(data, descriptor, expectedFormats, endObjectFormats) {
        return __awaiter(this, void 0, void 0, function* () {
            const resolveDescriptor = () => __awaiter(this, void 0, void 0, function* () {
                var _a;
                if (currentDescriptor.id && currentDescriptor.id !== mainId) {
                    throw new InvalidRequest("Each level of nesting of a descriptor map must have the same ID");
                }
                const path = (_a = currentDescriptor.path) !== null && _a !== void 0 ? _a : "$";
                if (!currentDescriptor.format) {
                    throw new InvalidRequest(`Descriptor ${currentDescriptor.id} needs to specify a format`);
                }
                const validAlgs = this.checkFormatValidity(expectedFormats, currentDescriptor.format);
                const tmp = this.resolveJsonPath(currentTraversalObject, path);
                if (!tmp.length) {
                    throw new InvalidRequest(`Descriptor ${currentDescriptor.id} json path does not resolve to any data`);
                }
                const parseResult = yield this.decodeAndParse(currentDescriptor.format, tmp[0], validAlgs, descriptor.id);
                currentTraversalObject = parseResult.data;
                lastJwa = parseResult.jwa;
            });
            let currentDescriptor = descriptor;
            const mainId = currentDescriptor.id;
            if (!currentDescriptor.id) {
                throw new InvalidRequest("Each input descriptor must have an ID");
            }
            let currentTraversalObject = data;
            let lastJwa;
            let lastFormat;
            do {
                yield resolveDescriptor();
                lastFormat = currentDescriptor.format;
                currentDescriptor = currentDescriptor.path_nested;
            } while (currentDescriptor);
            if (!currentTraversalObject.vc) {
                // If Json Linked Data is implemented, the condicional expression should change
                throw new InvalidRequest(`Submission resolution for descriptor ${descriptor.id} did not resolve in a valid VC`);
            }
            const validAlgs = this.checkFormatValidity(endObjectFormats, lastFormat);
            if (!validAlgs.includes(lastJwa)) {
                throw new InvalidRequest(`Unsupported JWA`);
            }
            return currentTraversalObject;
        });
    }
    resolveJsonPath(data, path) {
        if (path === "$") {
            return [data];
        }
        return jsonpath.query(data, path, 1);
    }
    resolveInputDescriptor(inputDescriptor, data) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            const result = {};
            if (inputDescriptor.constraints.fields) {
                for (const field of inputDescriptor.constraints.fields) {
                    if (!field.path.length) {
                        throw new InvalidRequest("At least one path must be specified for each field specification");
                    }
                    let claimFound;
                    let validPath;
                    for (const path of field.path) {
                        const tmp = jsonpath.query(data, path, 1);
                        if (tmp.length) {
                            if (field.filter) {
                                const validateFunction = yield ajv.compileAsync(field.filter);
                                const validationResult = validateFunction(tmp[0]);
                                if (validationResult) {
                                    claimFound = tmp[0];
                                    validPath = path;
                                    break;
                                }
                            }
                            else {
                                claimFound = tmp[0];
                                validPath = path;
                                break;
                            }
                        }
                    }
                    if (claimFound === undefined && !field.optional) {
                        throw new InvalidRequest(`Input descriptor ${inputDescriptor.id} not resolved`);
                    }
                    const entryId = (_a = field.id) !== null && _a !== void 0 ? _a : validPath;
                    result[entryId] = claimFound;
                }
            }
            return result;
        });
    }
    findDefinitionInputDescriptor(definition, id) {
        const result = definition.input_descriptors.find((descriptor) => descriptor.id === id);
        if (!result) {
            throw new InvalidRequest(`Invalid descriptor id: "${id}"`);
        }
        return result;
    }
}
function checkIfLdFormat(format) {
    return format.includes("ld");
}
