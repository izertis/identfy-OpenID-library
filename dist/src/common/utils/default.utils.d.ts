import { AuthServerMetadata } from '../interfaces/auth_server_metadata.interface.js';
/**
 * Generate a default metadata configuration for a Issuer according to EBSI
 * @param issuer The issuer identifier. It should be an URI
 * @returns Authorisation server metadata
 */
export declare function generateDefaultAuthorisationServerMetadata(issuer: string): AuthServerMetadata;
