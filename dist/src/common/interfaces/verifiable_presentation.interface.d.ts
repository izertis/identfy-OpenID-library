import { EmbeddedProof } from './w3c_verifiable_credential.interface.js';
export interface W3CVerifiablePresentation {
    '@context': string[];
    id?: string;
    type: ['VerifiablePresentation', ...string[]];
    holder?: string;
    proof?: EmbeddedProof;
    verifiableCredential?: string[] | Record<string, any>[];
}
