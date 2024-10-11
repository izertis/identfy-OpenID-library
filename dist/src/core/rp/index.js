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
import fetch from 'node-fetch';
import { Resolver } from "did-resolver";
import { decodeToken, verifyJwtWithExpAndAudience } from "../../common/utils/jwt.utils.js";
import { ACCESS_TOKEN_EXPIRATION_TIME, C_NONCE_EXPIRATION_TIME, DEFAULT_SCOPE, ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME } from "../../common/constants/index.js";
import { IdTokenRequest } from "../../common/classes/id_token_request.js";
import { AuthorizationResponse } from "../../common/classes/authz_response.js";
import { getAuthentificationJWKKeys } from "../../common/utils/did_document.js";
import { AccessDenied, InsufficienteParamaters, InternalError, InvalidGrant, InvalidRequest, InvalidScope, UnauthorizedClient, UnsupportedGrantType } from "../../common/classes/index.js";
import { VpResolver } from "../presentations/vp-resolver.js";
import { VpTokenRequest } from "../../common/classes/vp_token_request.js";
/**
 * Represents an entity acting as a Reliying Party. As such, it has the
 * capability to process authorisation requests and to send others.
 * It can also issue access tokens.
 *
 * The "grant_type" "authorisation_code" and "pre-authorised_code" are supported
 * for authentication.
 *
 */
export class OpenIDReliyingParty {
    /**
     * @param defaultMetadataCallback Callback to get the default value to
     * consider for client metadata.
     * @param metadata Authorisation server metadata
     * @param didResolver Object responsible for obtaining the DID Documents
     * of the DIDs that are detected.
     * @param vpCredentialVerificationCallback Optional callback needed to verify for
     * CredentialStatus and Verification
     */
    constructor(defaultMetadataCallback, metadata, didResolver, vpCredentialVerificationCallback) {
        this.defaultMetadataCallback = defaultMetadataCallback;
        this.metadata = metadata;
        this.didResolver = didResolver;
        this.vpCredentialVerificationCallback = vpCredentialVerificationCallback;
    }
    /**
     * Allows to add support for a new DID Method
     * @param methodName DID Method name
     * @param resolver Object responsible for obtaining the DID Documents
     * related to the DID specified
     */
    addDidMethod(methodName, resolver) {
        const tmp = {};
        tmp[methodName] = resolver;
        this.didResolver = new Resolver(Object.assign(Object.assign({}, this.didResolver), tmp));
    }
    /**
     * Allows to create a new Authorisation request in which an ID Token
     * is requested
     * @param clientAuthorizationEndpoint Endpoint of the authorisation
     * server of the client
     * @param audience "aud" parameter for the generated JWT.
     * @param redirectUri URI to which the client should deliver the
     * authorisation response to
     * @param jwtSignCallback Callback to generate the signed ID Token
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the ID Token.
     * @returns The ID Token Request
     */
    createIdTokenRequest(clientAuthorizationEndpoint, audience, redirectUri, jwtSignCallback, additionalParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            additionalParameters = Object.assign({
                responseMode: "direct_post",
                nonce: uuidv4(),
                scope: DEFAULT_SCOPE,
                expirationTime: ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME
            }, additionalParameters);
            const requestParams = {
                response_type: "id_token",
                scope: additionalParameters.scope,
                redirect_uri: redirectUri,
                response_mode: additionalParameters.responseMode,
                nonce: additionalParameters.nonce,
                client_id: this.metadata.issuer
            };
            if (additionalParameters.state) {
                requestParams.state = additionalParameters.state;
            }
            const idToken = yield jwtSignCallback(Object.assign(Object.assign({ aud: audience, iss: this.metadata.issuer, exp: Date.now() + additionalParameters.expirationTime }, requestParams), additionalParameters.additionalPayload), this.metadata.request_object_signing_alg_values_supported);
            return new IdTokenRequest(requestParams, idToken, clientAuthorizationEndpoint);
        });
    }
    /**
     * Allows to create a new Authorisation request in which an VP Token
     * is requested
     * @param clientAuthorizationEndpoint Endpoint of the authorisation
     * server of the client
     * @param audience "aud" parameter for the generated JWT.
     * @param redirectUri URI to which the client should deliver the
     * authorisation response to
     * @param jwtSignCallback Callback to generate the signed VP Token
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the VP Token.
     * @returns The VP Token Request
     */
    createVpTokenRequest(clientAuthorizationEndpoint, audience, redirectUri, jwtSignCallback, additionalParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            additionalParameters = Object.assign({
                responseMode: "direct_post",
                nonce: uuidv4(),
                scope: DEFAULT_SCOPE,
                expirationTime: ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME
            }, additionalParameters);
            const requestParams = {
                response_type: "vp_token",
                scope: additionalParameters.scope,
                redirect_uri: redirectUri,
                response_mode: additionalParameters.responseMode,
                nonce: additionalParameters.nonce,
                client_id: this.metadata.issuer
            };
            if (additionalParameters.state) {
                requestParams.state = additionalParameters.state;
            }
            if (additionalParameters.presentation_definition) {
                requestParams.presentation_definition =
                    additionalParameters.presentation_definition;
            }
            else if (additionalParameters.presentation_definition_uri) {
                requestParams.presentation_definition_uri =
                    additionalParameters.presentation_definition_uri;
            }
            else {
                throw new InvalidRequest("Either presentation_definition or presentation_definition URI must be defined");
            }
            const vpToken = yield jwtSignCallback(Object.assign(Object.assign({ aud: audience, iss: this.metadata.issuer, exp: Date.now() + additionalParameters.expirationTime }, requestParams), additionalParameters.additionalPayload), this.metadata.request_object_signing_alg_values_supported);
            return new VpTokenRequest(requestParams, vpToken, clientAuthorizationEndpoint);
        });
    }
    /**
     * Allows to verify an authorisation request sent by a client
     * @param request The request sent by the client
     * @param additionalParameters Optional parameters allowing
     * validations to be applied to the "scope", "authorisation_details"
     * and "issuer_state" parameters of the authorisation request
     * @returns Verified Authz Reques with some of the client metadata extracted
     */
    verifyBaseAuthzRequest(request, additionalParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            let params;
            let jwk = undefined;
            if (!request.request) {
                params = request;
            }
            else {
                if (this.metadata.request_parameter_supported === false) {
                    throw new InvalidRequest("Unsuported request parameter");
                }
                const { header, payload } = decodeToken(request.request);
                if (this.metadata.request_object_signing_alg_values_supported &&
                    !this.metadata.request_object_signing_alg_values_supported.includes(header.alg)) {
                    throw new InvalidRequest("Unsuported request signing alg");
                }
                params = payload;
                if (!params.client_metadata ||
                    "jwks_uri" in params.client_metadata === false) {
                    throw new InvalidRequest("Expected client metadata with jwks_uri");
                }
                const keys = yield fetchJWKs(params.client_metadata.jwks_uri);
                if (!header.kid) {
                    throw new InvalidRequest("No kid specify in JWT header");
                }
                jwk = selectJwkFromSet(keys, header.kid);
                try {
                    yield verifyJwtWithExpAndAudience(request.request, jwk, this.metadata.issuer);
                }
                catch (error) {
                    throw new InvalidRequest(error.message);
                }
            }
            params.client_metadata = yield this.resolveClientMetadata(params.client_metadata);
            const validatedClientMetadata = this.validateClientMetadata(params.client_metadata);
            if (additionalParameters) {
                if (additionalParameters.scopeVerifyCallback) {
                    const scopeVerificationResult = yield additionalParameters.scopeVerifyCallback(params.scope);
                    if (!scopeVerificationResult.valid) {
                        throw new InvalidScope(`Invalid scope specified` +
                            `${scopeVerificationResult.error ? ": " + scopeVerificationResult.error : '.'}`);
                    }
                }
                if (params.authorization_details) {
                    for (const details of params.authorization_details) {
                        if (details.locations &&
                            !details.locations.includes(this.metadata.issuer)) {
                            throw new InvalidRequest("Location must contains Issuer client id value");
                        }
                        if (additionalParameters.authzDetailsVerifyCallback) {
                            const authDetailsVerificationResult = yield additionalParameters.authzDetailsVerifyCallback(details);
                            if (!authDetailsVerificationResult.valid) {
                                throw new InvalidRequest(`Invalid authorization details specified` +
                                    `${authDetailsVerificationResult.error ? ": "
                                        + authDetailsVerificationResult.error : '.'}`);
                            }
                        }
                    }
                }
                if (additionalParameters.issuerStateVerifyCallback) {
                    if (!params.issuer_state) {
                        throw new InvalidRequest(`An "issuer_state" parameter is required`);
                    }
                    const issuerStateVerificationResult = yield additionalParameters.issuerStateVerifyCallback(params.issuer_state);
                    if (!issuerStateVerificationResult.valid) {
                        throw new InvalidRequest(`Invalid "issuer_state" provided` +
                            `${issuerStateVerificationResult.error ? ": "
                                + issuerStateVerificationResult.error : '.'}`);
                    }
                }
            }
            return {
                validatedClientMetadata,
                authzRequest: params,
                serviceWalletJWK: jwk
            };
        });
    }
    /**
     * Allows to verify an ID Token Response sent by a client
     * @param idTokenResponse The authorisation response to verify
     * @param verifyCallback A callback that allows to verify the contents of the
     * header and payload of the received ID Token, but no the signature
     * @returns The verified ID Token Response with the DID Document of the
     * associated token issuer.
     * @throws If data provided is incorrect
     */
    verifyIdTokenResponse(idTokenResponse, verifyCallback) {
        return __awaiter(this, void 0, void 0, function* () {
            const { header, payload } = decodeToken(idTokenResponse.id_token);
            const jwtPayload = payload;
            if (!jwtPayload.iss) {
                throw new InvalidRequest("Id Token must contain iss atribute");
            }
            if (!header.kid) {
                throw new InvalidRequest("No kid paramater found in ID Token");
            }
            if (this.metadata.id_token_signing_alg_values_supported
                && !this.metadata.id_token_signing_alg_values_supported.includes(header.alg)) {
                throw new InvalidRequest("Unsuported signing alg for ID Token");
            }
            const didResolution = yield this.didResolver.resolve(jwtPayload.iss);
            if (didResolution.didResolutionMetadata.error) {
                throw new UnauthorizedClient(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error}: ${didResolution.didResolutionMetadata.message}`);
            }
            const didDocument = didResolution.didDocument;
            const publicKeyJwk = getAuthentificationJWKKeys(didDocument, header.kid);
            try {
                yield verifyJwtWithExpAndAudience(idTokenResponse.id_token, publicKeyJwk, this.metadata.issuer);
            }
            catch (error) {
                throw new AccessDenied(error.message);
            }
            const verificationResult = yield verifyCallback(header, jwtPayload, didDocument);
            if (!verificationResult.valid) {
                throw new InvalidRequest(`ID Token verification failed ${verificationResult.error}`);
            }
            return {
                token: idTokenResponse.id_token,
                didDocument
            };
        });
    }
    /**
     * Allows to verify an VP Token Response sent by a client
     * @param vpTokenResponse The authorisation response to verify
     * @param presentationDefinition The presentation definition to use to
     * verify the VP
     * @param nonceVerificationCallback A callback used to verify the nonce of a JWT_VP
     * @param vcSignatureVerification A callback that can be used to perform additional
     * verification of any of the VC extracted from the VP. This can be used to check
     * the status of any VC and its terms of use.
     * @returns The verified VP Token Response with holder DID and the data
     * extracted from the VCs of the VP
     * @throws If data provided is incorrect
     */
    verifyVpTokenResponse(vpTokenResponse_1, presentationDefinition_1, nonceVerificationCallback_1) {
        return __awaiter(this, arguments, void 0, function* (vpTokenResponse, presentationDefinition, nonceVerificationCallback, vcSignatureVerification = true) {
            const vpResolver = new VpResolver(this.didResolver, this.metadata.issuer, this.vpCredentialVerificationCallback, nonceVerificationCallback, vcSignatureVerification);
            const claimData = yield vpResolver.verifyPresentation(vpTokenResponse.vp_token, presentationDefinition, vpTokenResponse.presentation_submission);
            return {
                token: vpTokenResponse.vp_token,
                vpInternalData: claimData
            };
        });
    }
    /**
     * Generates an authorisation response for a request with response type
     * "code".
     * @param redirect_uri The URI to send the response to
     * @param code The authorisation code to be sent
     * @param state The state to associate with the response. It must be
     * the same as the one sent by the client in the corresponding
     * authorisation request if this parameter was present.
     * @returns Authorization response
     */
    createAuthzResponse(redirect_uri, code, state) {
        return new AuthorizationResponse(redirect_uri, code, state);
    }
    /**
     * Allows to generate a token response from a token request
     * @param tokenRequest The token request sent by the client
     * @param generateIdToken Flag indicating whether, together with
     * the access token, an ID Token should be generated.
     * @param tokenSignCallback Callback that manages the signature of the token.
     * @param audience JWT "aud" to include in the generated access token
     * @param optionalParamaters Optional arguments to specify the nonce to be used, the time
     * validity of the nonce and callbacks to check the authorisation
     * and pre-authorisation codes sent. They also allow to specify how to
     * validate the code_challenge sent by the user in an authorisation request
     * @returns Token response with the generated access token
     * @throws If data provided is incorrect
     */
    generateAccessToken(tokenRequest, generateIdToken, tokenSignCallback, audience, optionalParamaters) {
        return __awaiter(this, void 0, void 0, function* () {
            let clientId = tokenRequest.client_id;
            if (this.metadata.grant_types_supported
                && !this.metadata.grant_types_supported.includes(tokenRequest.grant_type)) {
                throw new UnsupportedGrantType(`Grant type "${tokenRequest.grant_type}" not supported`);
            }
            switch (tokenRequest.grant_type) {
                case "authorization_code":
                    if (!tokenRequest.code) {
                        throw new InvalidGrant(`Grant type "${tokenRequest.grant_type}" invalid parameters`);
                    }
                    if (!optionalParamaters || !optionalParamaters.authorizeCodeCallback) {
                        throw new InsufficienteParamaters(`No verification callback was provided for "${tokenRequest.grant_type}" grant type`);
                    }
                    let verificationResult = yield optionalParamaters.authorizeCodeCallback(tokenRequest.client_id, tokenRequest.code);
                    if (!verificationResult.valid) {
                        throw new InvalidGrant(`Invalid "${tokenRequest.grant_type}" provided${verificationResult.error ?
                            ": " + verificationResult.error : '.'}`);
                    }
                    if (tokenRequest.client_assertion_type &&
                        tokenRequest.client_assertion_type ===
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
                        if (!tokenRequest.client_assertion) {
                            throw new InvalidRequest(`No "client_assertion" was provided`);
                        }
                        if (!optionalParamaters.retrieveClientAssertionPublicKeys) {
                            throw new InsufficienteParamaters(`No "retrieveClientAssertionPublickKeys" callback was provided`);
                        }
                        const keys = yield optionalParamaters.retrieveClientAssertionPublicKeys(clientId);
                        yield verifyJwtWithExpAndAudience(tokenRequest.client_assertion, keys, this.metadata.issuer);
                    }
                    else {
                        if (!optionalParamaters.codeVerifierCallback) {
                            throw new InsufficienteParamaters(`No "code_verifier" verification callback was provided.`);
                        }
                        verificationResult = yield optionalParamaters.codeVerifierCallback(tokenRequest.client_id, tokenRequest.code_verifier);
                        if (!verificationResult.valid) {
                            throw new InvalidGrant(`Invalid code_verifier provided${verificationResult.error ?
                                ": " + verificationResult.error : '.'}`);
                        }
                    }
                    break;
                case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
                    if (!tokenRequest["pre-authorized_code"]) {
                        throw new InvalidGrant(`Grant type "${tokenRequest.grant_type}" invalid parameters`);
                    }
                    if (!optionalParamaters || !optionalParamaters.preAuthorizeCodeCallback) {
                        throw new InsufficienteParamaters(`No verification callback was provided for "${tokenRequest.grant_type}" grant type`);
                    }
                    const verificationResultPre = yield optionalParamaters.preAuthorizeCodeCallback(tokenRequest.client_id, tokenRequest["pre-authorized_code"], tokenRequest.user_pin);
                    if (!verificationResultPre.client_id) {
                        throw new InvalidGrant(`Invalid "${tokenRequest.grant_type}" provided${verificationResultPre.error ?
                            ": " + verificationResultPre.error : '.'}`);
                    }
                    clientId = verificationResultPre.client_id;
                    break;
                case "vp_token":
                    if (!tokenRequest.vp_token) {
                        throw new InsufficienteParamaters(`Grant type "vp_token" requires the "vp_token" parameter`);
                    }
                    throw new InternalError("Uninplemented");
            }
            const cNonce = (optionalParamaters &&
                optionalParamaters.cNonceToEmploy) ?
                optionalParamaters.cNonceToEmploy : uuidv4();
            const tokenExp = (optionalParamaters &&
                optionalParamaters.accessTokenExp) ?
                optionalParamaters.accessTokenExp : ACCESS_TOKEN_EXPIRATION_TIME;
            const now = Math.floor(Date.now() / 1000);
            const token = yield tokenSignCallback({
                aud: audience,
                iss: this.metadata.issuer,
                sub: clientId,
                exp: now + tokenExp,
                nonce: cNonce,
            });
            const result = {
                access_token: token,
                token_type: "bearer",
                expires_in: tokenExp,
                c_nonce: cNonce,
                c_nonce_expires_in: (optionalParamaters &&
                    optionalParamaters.cNonceExp) ? optionalParamaters.cNonceExp : C_NONCE_EXPIRATION_TIME
            };
            if (generateIdToken) {
                result.id_token = yield tokenSignCallback({
                    iss: this.metadata.issuer,
                    sub: clientId,
                    exp: now + tokenExp,
                }, this.metadata.id_token_signing_alg_values_supported);
            }
            return result;
        });
    }
    validateClientMetadata(clientMetadata) {
        var _a, _b, _c;
        const idTokenAlg = [];
        const vpFormats = {};
        if (this.metadata.id_token_signing_alg_values_supported &&
            clientMetadata.id_token_signing_alg_values_supported) {
            for (const alg of clientMetadata.id_token_signing_alg_values_supported) {
                if (this.metadata.id_token_signing_alg_values_supported.includes(alg)) {
                    idTokenAlg.push(alg);
                }
            }
        }
        if (this.metadata.vp_formats_supported) {
            for (const format in clientMetadata.vp_formats_supported) {
                if (this.metadata.vp_formats_supported[format]) {
                    const intersectArray = [];
                    for (const alg of (_a = clientMetadata.vp_formats_supported[format]) === null || _a === void 0 ? void 0 : _a.alg_values_supported) {
                        if ((_b = this.metadata.vp_formats_supported[format]) === null || _b === void 0 ? void 0 : _b.alg_values_supported.includes(alg)) {
                            intersectArray.push(alg);
                        }
                    }
                    vpFormats[format] = {
                        alg_values_supported: intersectArray
                    };
                }
            }
        }
        return {
            responseTypesSupported: (_c = clientMetadata.response_types_supported) !== null && _c !== void 0 ? _c : [],
            idTokenAlg,
            vpFormats,
            authorizationEndpoint: clientMetadata.authorization_endpoint
        };
    }
    resolveClientMetadata(metadata) {
        return __awaiter(this, void 0, void 0, function* () {
            const defaultMetadata = yield this.defaultMetadataCallback();
            return metadata ? Object.assign(Object.assign({}, defaultMetadata), metadata) : defaultMetadata;
        });
    }
}
function fetchJWKs(url) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const response = yield fetch(url);
            const jwks = yield response.json();
            if (!jwks.keys) {
                throw new InvalidRequest("No 'keys' paramater found");
            }
            return jwks['keys'];
        }
        catch (e) {
            throw new InternalError(`Can't recover credential issuer JWKs: ${e}`);
        }
    });
}
function selectJwkFromSet(jwks, kid) {
    const jwk = jwks.find((jwk) => jwk.kid === kid);
    if (!jwk) {
        throw new InvalidRequest(`No JWK found with kid ${kid}`);
    }
    return jwk;
}
export * from "./types.js";
