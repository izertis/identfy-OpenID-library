import {JWK} from 'jose';
import {AuthzResponseType} from '@/types';

/**
 * It sets the requested VC Types, if they are known
 */
export type RequestVcTypes =
  | {type: 'Uknown'}
  | {type: 'Know'; vcTypes: string[]};

/**
 * It sets the Operation type, which be a VC issuance or a Verification
 */
export type OperationTypeEnum =
  | {type: 'Issuance'; vcTypes: RequestVcTypes}
  | {type: 'Verification'; scope: string};

/**
 * It sets the client information associated with the nonce
 */
export type ClientTypeEnum =
  | {
      type: 'HolderWallet';
      clientId: string;
      codeChallenge?: string;
      codeChallengeMethod?: string; // TODO: The method must be an algorithm
    }
  | {type: 'ServiceWallet'; clientJwk: JWK; clientId: string};

/**
 * All possible states that can be associated with a nonce
 */
export type NonceSpecificData =
  | PostBaseAuthzNonce
  | DirectRequestNonce
  | PostAuthzNonce
  | ChallengeNonce;

/**
 * The state for a nonce generated for a VP/ID Token Request after a base
 * authz request have been verified
 */
export interface PostBaseAuthzNonce {
  type: 'PostBaseAuthz';
  clientData: ClientTypeEnum;
  redirectUri: string;
  responseType: Extract<AuthzResponseType, 'id_token' | 'vp_token'>;
  holderState?: string;
  state?: string;
}

/**
 * The state for a nonce generated for a VP Token Request without
 * a previously verified authz request
 */
export interface DirectRequestNonce {
  type: 'DirectRequest';
  responseType: Extract<AuthzResponseType, 'id_token' | 'vp_token'>;
}

/**
 * The state for a nonce generated after a VP/ID Token response
 * have been verified
 */
export interface PostAuthzNonce {
  type: 'PostAuthz';
  clientData: ClientTypeEnum;
  redirectUri: string;
  responseType: Extract<AuthzResponseType, 'id_token' | 'vp_token'>;
}

/**
 * The state for a challenge nonce, which will be consumed in the
 * control proof of a credential request
 */
export interface ChallengeNonce {
  type: 'ChallengeNonce';
  expirationTime: number;
}

/**
 * An extension of every specific nonce states with general data
 */
export type NonceState = GeneralNonceData & NonceSpecificData;

/**
 * General data for all nonce's states
 */
export interface GeneralNonceData {
  timestamp: number;
  sub: string;
  operationType: OperationTypeEnum;
}
