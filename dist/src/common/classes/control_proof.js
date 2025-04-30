import { getAuthentificationJWKKeys } from '../utils/did_document.js';
import { decodeToken, obtainDid } from '../utils/jwt.utils.js';
import { importJWK, jwtVerify } from 'jose';
import { InvalidProof } from './error/index.js';
/**
 * Class defining the proof of possession of a key material.
 */
export class ControlProof {
    format;
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
            throw new InvalidProof('The "format" parameter is required in a control proof');
        }
        if (data.proof_type === 'jwt') {
            if (!data.jwt) {
                throw new InvalidProof('Proof of format "jwt" needs a "jwt" paramater');
            }
            return ControlProof.jwtProof(data.jwt);
        }
        else {
            throw new InvalidProof('Invalid format specified');
        }
    }
    /**
     * Allows to generate a proof in JWT format
     * @param jwt The JWT proof
     * @returns A JWT control proof
     */
    static jwtProof(jwt) {
        return new JwtControlProof('jwt', jwt);
    }
}
class JwtControlProof extends ControlProof {
    jwt;
    clientIdentifier;
    constructor(format, jwt) {
        super(format);
        this.jwt = jwt;
    }
    toJSON() {
        return {
            format: this.format,
            jwt: this.jwt,
        };
    }
    getAssociatedIdentifier() {
        if (!this.clientIdentifier) {
            const { header, payload } = decodeToken(this.jwt);
            if (!header.kid) {
                throw new InvalidProof('"kid" parameter must be specified');
            }
            this.clientIdentifier = obtainDid(header.kid, payload.iss);
        }
        return this.clientIdentifier;
    }
    getInnerNonce() {
        const { payload } = decodeToken(this.jwt);
        const jwtPayload = payload;
        if (!jwtPayload.nonce) {
            throw new InvalidProof('"nonce" parameter is not specified');
        }
        return jwtPayload.nonce;
    }
    async verifyProof(cNonce, audience, didResolver) {
        const { header, payload } = decodeToken(this.jwt);
        const jwtPayload = payload;
        if (!header.typ || header.typ !== 'openid4vci-proof+jwt') {
            throw new InvalidProof('Invalid "typ" paramater in proof header');
        }
        if (header.alg === 'none') {
            throw new InvalidProof('The value of "alg" parameter can\'t be none');
        }
        if (!header.kid) {
            throw new InvalidProof('"kid" parameter must be specified');
        }
        if (!jwtPayload.aud || jwtPayload.aud !== audience) {
            throw new InvalidProof('"aud" parameter is not specified or is invalid');
        }
        if (!jwtPayload.iat) {
            throw new InvalidProof('"iat" parameter must be specified');
        }
        if (!jwtPayload.nonce || jwtPayload.nonce !== cNonce) {
            throw new InvalidProof('"nonce" parameter is not specified or is invalid');
        }
        const did = this.clientIdentifier ?? obtainDid(header.kid, jwtPayload.iss);
        const didResolution = await didResolver.resolve(did);
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
        const publicKey = await importJWK(publicKeyJwk);
        await jwtVerify(this.jwt, publicKey, { clockTolerance: 5 });
    }
}
//# sourceMappingURL=control_proof.js.map