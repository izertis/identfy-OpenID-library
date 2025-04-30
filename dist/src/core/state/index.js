/**
 * A class that implements a key-value interface to handle states.
 * The user of the library must generate an implementation in order
 * for a RP and a VcIssuer to work.
 */
export class StateManager {
}
/**
 * Basic In-Memory implementation of the StateManager interface.
 * Its use is inteded for tests and development
 */
export class MemoryStateManager extends StateManager {
    memory = {};
    constructor() {
        super();
    }
    async saveState(id, data) {
        this.memory[id] = data;
    }
    async updateState(id, data) {
        this.memory[id] = data;
    }
    getState(id) {
        return this.memory[id];
    }
    async deleteState(id) {
        delete this.memory[id];
    }
}
//# sourceMappingURL=index.js.map