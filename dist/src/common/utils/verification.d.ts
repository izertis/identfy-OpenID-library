import { VerificationResult } from '../types/index.js';
/**
 * Utility function that can be used in almost all verification callbacks
 * of the differents components of this library
 * @param _data Any amount of data
 * @returns Allways returns a valid verification
 */
export declare function alwaysAcceptVerification(..._data: any[]): Promise<VerificationResult>;
