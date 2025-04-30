import { W3CVerifiableCredentialFormats, W3CVerifiablePresentationFormats } from '../formats/index.js';
/**
 * Presentation Submission data structure according to
 * https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission
 */
export interface DIFPresentationSubmission {
    id: string;
    definition_id: string;
    descriptor_map: DescriptorMap[];
}
/**
 * Defines how to relate the VCs delivered in a VP to the requirements of a definition.
 */
export interface DescriptorMap {
    id: string;
    format: W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats;
    path?: string;
    path_nested?: DescriptorMap;
}
