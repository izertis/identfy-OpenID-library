import { W3CVerifiableCredentialFormats } from "../formats/index.js";
import { BaseControlProof } from "./control_proof.interface.js";

/**
 * Defines a credential request object in accordance to OID4VCI
 */
export interface CredentialRequest {
  types: string[];
  format: W3CVerifiableCredentialFormats;
  proof: BaseControlProof
}
