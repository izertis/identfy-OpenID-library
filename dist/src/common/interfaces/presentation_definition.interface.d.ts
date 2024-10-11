import { JWA_ALGS } from "../constants";
import { W3CVerifiableCredentialFormats, W3CVerifiablePresentationFormats } from "../formats";
/**
 * Data structure of a presentation definition according to
 * https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition
 */
export interface DIFPresentationDefinition {
    id: string;
    input_descriptors: PresentationInputDescriptor[];
    name?: string;
    purpose?: string;
    format: LdFormat & JwtFormat;
}
/**
 * Describe information that the verifiers needs from the client.
 * Based on https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor
 */
export interface PresentationInputDescriptor {
    id: string;
    name?: string;
    purpose?: string;
    format?: LdFormat & JwtFormat;
    constraints: InputDescriptorContraintType;
}
/**
 * Defines the restrictions that an InputDescriptor must fulfill.
 */
export interface InputDescriptorFielType {
    path: string[];
    id?: string;
    purpose?: string;
    name?: string;
    filter?: Record<string, unknown>;
    optional?: boolean;
}
/**
 * Specifies the fields that the delivered VCs should comply with
 */
export interface InputDescriptorContraintType {
    fields?: InputDescriptorFielType[];
    limit_disclosure?: 'required' | 'preferred';
}
/**
 * Specifies the valid formats that use JLD
 * Based on https://identity.foundation/claim-format-registry/#registry
 */
export type LdFormat = {
    [key in keyof Pick<W3CVerifiableCredentialFormats & W3CVerifiablePresentationFormats, "jwt_vc_json-ld" | "ldp_vc" | "ldp_vp">]?: {
        proof_type: string;
    };
};
/**
 * Specifies the valid formats that use JWT
 * Based on https://identity.foundation/claim-format-registry/#registry
 */
export type JwtFormat = {
    [key in keyof Pick<W3CVerifiableCredentialFormats & W3CVerifiablePresentationFormats, "jwt_vc_json" | "jwt_vc" | "jwt_vp_json" | "jwt_vp">]?: {
        alg: Exclude<JWA_ALGS, "none">[];
    };
};
