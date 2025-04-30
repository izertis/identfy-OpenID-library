export declare abstract class NonceError extends Error {
    nonceId: string;
    constructor(nonceId: string);
}
export declare class NonceNotFound extends NonceError {
    nonceId: string;
    constructor(nonceId: string);
}
export declare class InternalNonceError extends NonceError {
    nonceId: string;
    constructor(nonceId: string);
}
export declare class InvalidNonceStage extends NonceError {
    nonceId: string;
    constructor(nonceId: string, expectedStage: string, currentStage: string);
}
