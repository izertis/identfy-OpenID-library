import {Result} from '../../common/classes/result.js';
import {
  InvalidNonceStage,
  NonceError,
  NonceNotFound,
} from '../../common/index.js';
import {StateManager} from '../state/index.js';
import {
  ChallengeNonce,
  GeneralNonceData,
  NonceState,
  NonceSpecificData,
  PostAuthzNonce,
  PostBaseAuthzNonce,
  DirectRequestNonce,
} from './types.js';

/**
 * Class that allows the management of the nonces generated together
 * with their states using an interface that simulates a key-value database.
 */
export class NonceManager {
  constructor(private stateManager: StateManager) {}

  // TODO: Evaluate the use of result
  /**
   * Allows to save a nonce and its associated state
   * @param id The nonce itself
   * @param data The data associated to the nonce
   */
  async saveNonce(id: string, data: NonceState) {
    await this.stateManager.saveState(id, data);
  }

  async updateNonce(id: string, data: NonceState) {
    await this.stateManager.updateState(id, data);
  }

  /**
   * Allows to erase a nonce and its data
   * @param id The nonce to delete
   */
  async deleteNonce(id: string) {
    await this.stateManager.deleteState(id);
  }

  private async getNonce(
    id: string,
    expectedStage: Extract<NonceSpecificData, {type: string}>['type'],
  ): Promise<Result<NonceState, NonceError>> {
    const nonce = await this.stateManager.getState(id);
    if (!nonce) {
      return Result.Err(new NonceNotFound(id));
    }
    if (nonce.type !== expectedStage) {
      return Result.Err(new InvalidNonceStage(id, expectedStage, nonce.type));
    }
    return Result.Ok(nonce);
  }

  /**
   * Get the nonce specified and checks if its state if of the type "PostBaseAuthz"
   * @param id The nonce itself to get its state
   * @returns The state of the nonce
   */
  async getPostBaseAuthzNonce(
    id: string,
  ): Promise<Result<GeneralNonceData & PostBaseAuthzNonce, NonceError>> {
    return (await this.getNonce(id, 'PostBaseAuthz')) as Result<
      GeneralNonceData & PostBaseAuthzNonce,
      NonceError
    >;
  }

  /**
   * Get the nonce specified and checks if its state if of the type "DirectRequest"
   * @param id The nonce itself to get its state
   * @returns The state of the nonce
   */
  async getDirectRequestNonce(
    id: string,
  ): Promise<Result<GeneralNonceData & DirectRequestNonce, NonceError>> {
    return (await this.getNonce(id, 'DirectRequest')) as Result<
      GeneralNonceData & DirectRequestNonce,
      NonceError
    >;
  }

  /**
   * Get the nonce specified and checks if its state if of the type "PostAuthz"
   * @param id The nonce itself to get its state
   * @returns The state of the nonce
   */
  async getPostAuthz(
    id: string,
  ): Promise<Result<GeneralNonceData & PostAuthzNonce, NonceError>> {
    return (await this.getNonce(id, 'PostAuthz')) as Result<
      GeneralNonceData & PostAuthzNonce,
      NonceError
    >;
  }

  /**
   * Get the nonce specified and checks if its state if of the type "ChallengeNonce"
   * @param id The nonce itself to get its state
   * @returns The state of the nonce
   */
  async getChallengeNonce(
    id: string,
  ): Promise<Result<GeneralNonceData & ChallengeNonce, NonceError>> {
    return (await this.getNonce(id, 'ChallengeNonce')) as Result<
      GeneralNonceData & ChallengeNonce,
      NonceError
    >;
  }
}

export * from './types.js';
