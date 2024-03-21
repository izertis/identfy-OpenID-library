import { ControlProofType } from "../types/index.js";
/**
 * Defines a proof of possesion in accordance to OID4VCI
 */
export interface BaseControlProof {
    proof_type: ControlProofType;
    [key: string]: any;
}
