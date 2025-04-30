import {JWA_ALGS} from '../constants/index.js';
import {ControlProofType} from '../types/index.js';
import {getAuthentificationJWKKeys} from '../utils/did_document.js';
import {decodeToken, obtainDid} from '../utils/jwt.utils.js';
import {Resolvable} from 'did-resolver';
import {importJWK, jwtVerify} from 'jose';
import {JwtPayload} from 'jsonwebtoken';
import {InvalidProof} from './error/index.js';

/**
 * Class defining the proof of possession of a key material.
 */
export abstract class ControlProof {
  protected constructor(public format: ControlProofType) {}

  /**
   * Allows to obtain the DID of the user that generated the proof
   */
  abstract getAssociatedIdentifier(): string;

  /**
   * Allows to obtain the nonce included in the proof
   */
  abstract getInnerNonce(): string;

  /**
   * Express the proof as a object that contains only the attributes
   */
  abstract toJSON(): Record<string, string>;
  /**
   * Allows to verify a proof
   * @param cNonce Challenge nonce that should contain the proof
   * @param audience Expected audicente of the proof
   * @param didResolver Object that allows to resolve the DIDs found in the proof
   * @throws if the proof is invalid for any reason
   */
  abstract verifyProof(
    cNonce: string,
    audience: string,
    didResolver: Resolvable,
  ): Promise<void>;

  /**
   * Allows to generate an instance of this class from a generic object
   * @param data The object from which generate the proof
   * @returns An object of this class
   * @throws if the object provided is not a valid proof
   */
  static fromJSON(data: Record<string, any>): ControlProof {
    if (!data.proof_type) {
      throw new InvalidProof(
        'The "format" parameter is required in a control proof',
      );
    }
    if (data.proof_type === 'jwt') {
      if (!data.jwt) {
        throw new InvalidProof('Proof of format "jwt" needs a "jwt" paramater');
      }
      return ControlProof.jwtProof(data.jwt);
    } else {
      throw new InvalidProof('Invalid format specified');
    }
  }

  /**
   * Allows to generate a proof in JWT format
   * @param jwt The JWT proof
   * @returns A JWT control proof
   */
  static jwtProof(jwt: string): JwtControlProof {
    return new JwtControlProof('jwt', jwt);
  }
}

class JwtControlProof extends ControlProof {
  private clientIdentifier?: string;

  constructor(
    format: ControlProofType,
    private jwt: string,
  ) {
    super(format);
  }

  toJSON(): Record<string, string> {
    return {
      format: this.format,
      jwt: this.jwt,
    };
  }

  getAssociatedIdentifier(): string {
    if (!this.clientIdentifier) {
      const {header, payload} = decodeToken(this.jwt);
      if (!header.kid) {
        throw new InvalidProof('"kid" parameter must be specified');
      }
      this.clientIdentifier = obtainDid(
        header.kid,
        (payload as JwtPayload).iss,
      );
    }
    return this.clientIdentifier;
  }

  getInnerNonce(): string {
    const {payload} = decodeToken(this.jwt);
    const jwtPayload = payload as JwtPayload;
    if (!jwtPayload.nonce) {
      throw new InvalidProof('"nonce" parameter is not specified');
    }
    return jwtPayload.nonce;
  }

  async verifyProof(
    cNonce: string,
    audience: string,
    didResolver: Resolvable,
  ): Promise<void> {
    const {header, payload} = decodeToken(this.jwt);
    const jwtPayload = payload as JwtPayload;
    if (!header.typ || header.typ !== 'openid4vci-proof+jwt') {
      throw new InvalidProof('Invalid "typ" paramater in proof header');
    }
    if ((header.alg as JWA_ALGS) === 'none') {
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
      throw new InvalidProof(
        '"nonce" parameter is not specified or is invalid',
      );
    }
    const did = this.clientIdentifier ?? obtainDid(header.kid, jwtPayload.iss);
    const didResolution = await didResolver.resolve(did);
    if (didResolution.didResolutionMetadata.error) {
      throw new InvalidProof(
        `Did resolution failed. Error ${
          didResolution.didResolutionMetadata.error
        }: ${didResolution.didResolutionMetadata.message}`,
      );
    }
    const didDocument = didResolution.didDocument!;
    let publicKeyJwk;
    try {
      publicKeyJwk = getAuthentificationJWKKeys(didDocument, header.kid);
    } catch (error: any) {
      throw new InvalidProof(error.message);
    }
    const publicKey = await importJWK(publicKeyJwk);
    await jwtVerify(this.jwt, publicKey, {clockTolerance: 5});
  }
}
