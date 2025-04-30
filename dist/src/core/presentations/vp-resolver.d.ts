import { Resolver } from 'did-resolver';
import { DIFPresentationDefinition, DIFPresentationSubmission } from '../../common/interfaces/index.js';
import { CredentialAdditionalVerification, NonceAndStateVerification, VpExtractedData } from './types.js';
/**
 * Component specialized in the verification of verifiable
 * submissions, for which it requires the original definition
 * and the submission delivered together with the VP.
 */
export declare class VpResolver {
    private didResolver;
    private audience;
    private externalValidation;
    private nonceAndStateValidation;
    private vcSignatureVerification;
    private jwtCache;
    private vpHolder;
    /**
     * Main constructor of this class
     * @param didResolver The DID Resolver to employ
     * @param audience The expected audience in the tokens that will be processed
     * @param externalValidation Callback that will be used to request external
     * verification of any detected VC. This verification should focus on
     * validating issues related to the trust framework and the use case.
     * @param nonceAndStateValidation Callback the nonces specified in any JWT VP
     * @param vcSignatureVerification Flag indicating whether the signatures of the VCs
     * included in the VP should be verified. To that regard, the DID Resolver provided must
     * be able to generate the needed DID Documents
     */
    constructor(didResolver: Resolver, audience: string, externalValidation: CredentialAdditionalVerification, nonceAndStateValidation: NonceAndStateVerification, vcSignatureVerification?: boolean);
    /**
     * Verify a Verifiable Presentation
     * @param vp Any data structure in which the VP is located
     * @param definition The definition of the presentation to be
     * used to verify the PV
     * @param submission The presentation submission submitted with the VP
     * @returns Data extracted from the credentials contained
     * in the VP as indicated in the definition provided.
     */
    verifyPresentation(vp: any, definition: DIFPresentationDefinition, submission: DIFPresentationSubmission): Promise<VpExtractedData>;
    private deserializeJwtVc;
    private getSchema;
    private decodeAndParse;
    private deserializeJwtVp;
    private verifyVcDates;
    private checkVcDataModel;
    private checkFormatValidity;
    private extractCredentialFromVp;
    private resolveJsonPath;
    private resolveInputDescriptor;
    private findDefinitionInputDescriptor;
}
