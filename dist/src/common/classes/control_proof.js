var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { getAuthentificationJWKKeys } from "../utils/did_document.js";
import { decodeToken, obtainDid } from "../utils/jwt.utils.js";
import { importJWK, jwtVerify } from "jose";
import { InvalidProof } from "./error/index.js";
/**
 * Class defining the proof of possession of a key material.
 */
export class ControlProof {
    constructor(format) {
        this.format = format;
    }
    /**
     * Allows to generate an instance of this class from a generic object
     * @param data The object from which generate the proof
     * @returns An object of this class
     * @throws if the object provided is not a valid proof
     */
    static fromJSON(data) {
        if (!data.proof_type) {
            throw new InvalidProof(`The "format" parameter is required in a control proof`);
        }
        if (data.proof_type === "jwt") {
            if (!data.jwt) {
                throw new InvalidProof(`Proof of format "jwt" needs a "jwt" paramater`);
            }
            return ControlProof.jwtProof(data.jwt);
        }
        else {
            throw new InvalidProof("Invalid format specified");
        }
    }
    /**
     * Allows to generate a proof in JWT format
     * @param jwt The JWT proof
     * @returns A JWT control proof
     */
    static jwtProof(jwt) {
        return new JwtControlProof("jwt", jwt);
    }
}
class JwtControlProof extends ControlProof {
    constructor(format, jwt) {
        super(format);
        this.jwt = jwt;
    }
    toJSON() {
        return {
            format: this.format,
            jwt: this.jwt
        };
    }
    getAssociatedIdentifier() {
        if (!this.clientIdentifier) {
            const { header, payload } = decodeToken(this.jwt);
            if (!header.kid) {
                throw new InvalidProof(`"kid" parameter must be specified`);
            }
            this.clientIdentifier = obtainDid(header.kid, payload.iss);
        }
        return this.clientIdentifier;
    }
    verifyProof(cNonce, audience, didResolver) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { header, payload } = decodeToken(this.jwt);
            const jwtPayload = payload;
            if (!header.typ || header.typ !== "openid4vci-proof+jwt") {
                throw new InvalidProof(`Invalid "typ" paramater in proof header`);
            }
            if (header.alg === "none") {
                throw new InvalidProof(`The value of "alg" parameter can't be none`);
            }
            if (!header.kid) {
                throw new InvalidProof(`"kid" parameter must be specified`);
            }
            if (!jwtPayload.aud || jwtPayload.aud !== audience) {
                throw new InvalidProof(`"aud" parameter is not specified or is invalid`);
            }
            if (!jwtPayload.iat) {
                throw new InvalidProof(`"iat" parameter must be specified`);
            }
            if (!jwtPayload.nonce || jwtPayload.nonce !== cNonce) {
                throw new InvalidProof(`"nonce" parameter is not specified or is invalid`);
            }
            const did = (_a = this.clientIdentifier) !== null && _a !== void 0 ? _a : obtainDid(header.kid, jwtPayload.iss);
            const didResolution = yield didResolver.resolve(did);
            if (didResolution.didResolutionMetadata.error) {
                throw new InvalidProof(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error}: ${didResolution.didResolutionMetadata.message}`);
            }
            const didDocument = didResolution.didDocument;
            let publicKeyJwk;
            try {
                publicKeyJwk = getAuthentificationJWKKeys(didDocument, header.kid);
            }
            catch (error) {
                throw new InvalidProof(error.message);
            }
            const publicKey = yield importJWK(publicKeyJwk);
            yield jwtVerify(this.jwt, publicKey);
        });
    }
}
