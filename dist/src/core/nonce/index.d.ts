import { Result } from '../../common/classes/result.js';
import { NonceError } from '../../common/index.js';
import { StateManager } from '../state/index.js';
import { ChallengeNonce, GeneralNonceData, NonceState, PostAuthzNonce, PostBaseAuthzNonce, DirectRequestNonce } from './types.js';
/**
 * Class that allows the management of the nonces generated together
 * with their states using an interface that simulates a key-value database.
 */
export declare class NonceManager {
    private stateManager;
    constructor(stateManager: StateManager);
    /**
     * Allows to save a nonce and its associated state
     * @param id The nonce itself
     * @param data The data associated to the nonce
     */
    saveNonce(id: string, data: NonceState): Promise<void>;
    updateNonce(id: string, data: NonceState): Promise<void>;
    /**
     * Allows to erase a nonce and its data
     * @param id The nonce to delete
     */
    deleteNonce(id: string): Promise<void>;
    private getNonce;
    /**
     * Get the nonce specified and checks if its state if of the type "PostBaseAuthz"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getPostBaseAuthzNonce(id: string): Promise<Result<GeneralNonceData & PostBaseAuthzNonce, NonceError>>;
    /**
     * Get the nonce specified and checks if its state if of the type "DirectRequest"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getDirectRequestNonce(id: string): Promise<Result<GeneralNonceData & DirectRequestNonce, NonceError>>;
    /**
     * Get the nonce specified and checks if its state if of the type "PostAuthz"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getPostAuthz(id: string): Promise<Result<GeneralNonceData & PostAuthzNonce, NonceError>>;
    /**
     * Get the nonce specified and checks if its state if of the type "ChallengeNonce"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getChallengeNonce(id: string): Promise<Result<GeneralNonceData & ChallengeNonce, NonceError>>;
}
export * from './types.js';
