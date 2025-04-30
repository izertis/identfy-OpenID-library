import { Result } from '../../common/classes/result.js';
import { InvalidNonceStage, NonceNotFound, } from '../../common/index.js';
/**
 * Class that allows the management of the nonces generated together
 * with their states using an interface that simulates a key-value database.
 */
export class NonceManager {
    stateManager;
    constructor(stateManager) {
        this.stateManager = stateManager;
    }
    // TODO: Evaluate the use of result
    /**
     * Allows to save a nonce and its associated state
     * @param id The nonce itself
     * @param data The data associated to the nonce
     */
    async saveNonce(id, data) {
        await this.stateManager.saveState(id, data);
    }
    async updateNonce(id, data) {
        await this.stateManager.updateState(id, data);
    }
    /**
     * Allows to erase a nonce and its data
     * @param id The nonce to delete
     */
    async deleteNonce(id) {
        await this.stateManager.deleteState(id);
    }
    async getNonce(id, expectedStage) {
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
    async getPostBaseAuthzNonce(id) {
        return (await this.getNonce(id, 'PostBaseAuthz'));
    }
    /**
     * Get the nonce specified and checks if its state if of the type "DirectRequest"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    async getDirectRequestNonce(id) {
        return (await this.getNonce(id, 'DirectRequest'));
    }
    /**
     * Get the nonce specified and checks if its state if of the type "PostAuthz"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    async getPostAuthz(id) {
        return (await this.getNonce(id, 'PostAuthz'));
    }
    /**
     * Get the nonce specified and checks if its state if of the type "ChallengeNonce"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    async getChallengeNonce(id) {
        return (await this.getNonce(id, 'ChallengeNonce'));
    }
}
export * from './types.js';
//# sourceMappingURL=index.js.map