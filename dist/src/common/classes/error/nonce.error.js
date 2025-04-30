export class NonceError extends Error {
    nonceId;
    constructor(nonceId) {
        super();
        this.nonceId = nonceId;
    }
}
export class NonceNotFound extends NonceError {
    nonceId;
    constructor(nonceId) {
        super(nonceId);
        this.nonceId = nonceId;
        this.message = `Nonce ${nonceId} not found`;
    }
}
export class InternalNonceError extends NonceError {
    nonceId;
    constructor(nonceId) {
        super(nonceId);
        this.nonceId = nonceId;
        this.message = `Internal error retrieving nonce ${nonceId}`;
    }
}
export class InvalidNonceStage extends NonceError {
    nonceId;
    constructor(nonceId, expectedStage, currentStage) {
        super(nonceId);
        this.nonceId = nonceId;
        this.message = `Nonce ${nonceId} expected stage "${expectedStage}" but "${currentStage}" was found`;
    }
}
//# sourceMappingURL=nonce.error.js.map