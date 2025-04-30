import {KeyLike} from 'jose';
import {W3CDataModel} from '../../common/formats/index.js';
import {W3CVerifiableCredential} from '../../common/interfaces/index.js';
import {Result} from '../../common/classes/result.js';

/**
 * Callback type that is used to perfom additional verifications of a VC.
 * It can be used to check the credentialStatus parameter and the terms of use.
 * @param vc The VC that has to be verified
 * @param dmVersion The data model version in accordance to W3C VC
 * @param issuerPublickKey The publickKey of the issuer that issued the VC.
 * It will be undefined only if VC Signature verification is dissabled.
 * @returns Indication of whether the verification was successful
 * accompanied by an optional error message
 */
export type CredentialAdditionalVerification = (
  vc: W3CVerifiableCredential,
  dmVersion: W3CDataModel,
  issuerPublickKey?: KeyLike | Uint8Array,
) => Promise<Result<null, Error>>;

/**
 * Callback type that is used to verify the nonce value of a VP Token
 * @param subject The holder of the VP Token
 * @param nonce The nonce specified in the VP Token
 * @returns Indication of whether the verification was successful
 * accompanied by an optional error message
 */
export type NonceAndStateVerification = (
  subject: string,
  nonce: string,
  state?: string,
) => Promise<Result<null, Error>>;

/**
 * Data extracted from verifiable credentials contained in a VP as
 * indicated in a submission definition. For each dataset, the key
 *  corresponds to the provided identifier or, if this has not been
 *  provided, by the JSON PATH used to obtain the credential data.
 */
export type VpExtractedData = {
  /**
   * The data extracted from the VCs in the VP
   */
  claimsData: Record<string, any>;
  /**
   * The DID of the holder of the VP
   */
  holderDid: string;
};
