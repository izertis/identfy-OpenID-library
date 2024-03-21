import { W3CVerifiableCredentialFormats } from "../formats/index.js";
import { W3CVerifiableCredentialV2 } from "./w3c_verifiable_credential.interface.js";
import { CompactVc } from "../types/index.js";
/**
 * Defines a credential response object in accordance to OID4VCI
 */
export interface CredentialResponse {
    format?: W3CVerifiableCredentialFormats;
    credential?: W3CVerifiableCredentialV2 | CompactVc;
    acceptance_token?: string;
    c_nonce?: string;
    c_nonce_expires_in?: number;
}
