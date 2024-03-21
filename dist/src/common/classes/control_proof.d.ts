import { ControlProofType } from "../types/index.js";
import { Resolvable } from "did-resolver";
/**
 * Class defining the proof of possession of a key material.
 */
export declare abstract class ControlProof {
    format: ControlProofType;
    protected constructor(format: ControlProofType);
    /**
     * Allows to obtain the DID of the user that generated the proof
     */
    abstract getAssociatedIdentifier(): string;
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
    abstract verifyProof(cNonce: string, audience: string, didResolver: Resolvable): Promise<void>;
    /**
     * Allows to generate an instance of this class from a generic object
     * @param data The object from which generate the proof
     * @returns An object of this class
     * @throws if the object provided is not a valid proof
     */
    static fromJSON(data: Record<string, any>): ControlProof;
    /**
     * Allows to generate a proof in JWT format
     * @param jwt The JWT proof
     * @returns A JWT control proof
     */
    static jwtProof(jwt: string): JwtControlProof;
}
declare class JwtControlProof extends ControlProof {
    private jwt;
    private clientIdentifier?;
    constructor(format: ControlProofType, jwt: string);
    toJSON(): Record<string, string>;
    getAssociatedIdentifier(): string;
    verifyProof(cNonce: string, audience: string, didResolver: Resolvable): Promise<void>;
}
export {};
