import {EmbeddedProof} from './w3c_verifiable_credential.interface.js';

// https://www.w3.org/TR/vc-data-model/#presentations-0
// https://www.w3.org/TR/vc-data-model-2.0/#presentations-0
export interface W3CVerifiablePresentation {
  '@context': string[]; // TODO: Maybe use a custom type like the one below
  id?: string;
  type: ['VerifiablePresentation', ...string[]];
  holder?: string;
  proof?: EmbeddedProof;
  verifiableCredential?: string[] | Record<string, any>[];
}
