import {JwtPayload} from 'jsonwebtoken';
import {W3CVerifiablePresentation} from './verifiable_presentation.interface.js';
import {DIFPresentationSubmission} from './presentation_submission.interface.js';

/**
 * Defines an authorization response for the response type "vp_token"
 */
export interface VpTokenResponse {
  vp_token: string;
  presentation_submission: DIFPresentationSubmission;
  [key: string]: any;
}

/**
 * Defines the payload of an VP Token
 */
export interface JwtVpPayload extends JwtPayload {
  vp: W3CVerifiablePresentation;
}
