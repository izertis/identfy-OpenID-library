export declare class OpenIdError extends Error {
    code: string;
    message: string;
    recommendedHttpStatus?: number | undefined;
    redirectUri?: string | undefined;
    holderState?: string | undefined;
    constructor(code: string, message: string, recommendedHttpStatus?: number | undefined, redirectUri?: string | undefined, holderState?: string | undefined);
    toRfcSpecification(): {
        status: number | undefined;
        error: {
            code: string;
            erro_description: string;
        };
    };
}
export declare class InvalidRequest extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class AccessDenied extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class InvalidClient extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class InvalidGrant extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class UnauthorizedClient extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class UnsupportedGrantType extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class InvalidScope extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class InvalidToken extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class InsufficientScope extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class InvalidCredentialRequest extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class UnsupportedCredentialType extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class UnsupportedCredentialFormat extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class InvalidProof extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class UnsupportedResponseType extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
export declare class VpFormatsNotSupported extends OpenIdError {
    constructor(message: string, redirectUri?: string, holderState?: string);
}
