export class OpenIdError extends Error {
    code;
    message;
    recommendedHttpStatus;
    redirectUri;
    holderState;
    constructor(code, message, recommendedHttpStatus, redirectUri, holderState) {
        super();
        this.code = code;
        this.message = message;
        this.recommendedHttpStatus = recommendedHttpStatus;
        this.redirectUri = redirectUri;
        this.holderState = holderState;
    }
    toRfcSpecification() {
        return {
            status: this.recommendedHttpStatus,
            error: {
                code: this.code,
                erro_description: this.message,
            },
        };
    }
}
export class InvalidRequest extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('invalid_request', message, 400, redirectUri, holderState);
    }
}
export class AccessDenied extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('access_denied', message, 403, redirectUri, holderState);
    }
}
export class InvalidClient extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('invalid_client', message, 401, redirectUri, holderState);
    }
}
export class InvalidGrant extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('invalid_grant', message, 400, redirectUri, holderState);
    }
}
export class UnauthorizedClient extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('unauthorized_client', message, 400, redirectUri, holderState);
    }
}
export class UnsupportedGrantType extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('unsupported_grant_type', message, 400, redirectUri, holderState);
    }
}
export class InvalidScope extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('invalid_scope', message, 400, redirectUri, holderState);
    }
}
export class InvalidToken extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('invalid_token', message, 401, redirectUri, holderState);
    }
}
export class InsufficientScope extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('insufficient_scope', message, 403, redirectUri, holderState);
    }
}
export class InvalidCredentialRequest extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('invalid_credential_request', message, 400, redirectUri, holderState);
    }
}
export class UnsupportedCredentialType extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('unsupported_credential_type', message, 400, redirectUri, holderState);
    }
}
export class UnsupportedCredentialFormat extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('unsupported_credential_format', message, 400, redirectUri, holderState);
    }
}
export class InvalidProof extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('invalid_proof', message, 400, redirectUri, holderState);
    }
}
export class UnsupportedResponseType extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('unsupported_response_type', message, 400, redirectUri, holderState);
    }
}
export class VpFormatsNotSupported extends OpenIdError {
    constructor(message, redirectUri, holderState) {
        super('vp_formats_not_supported', message, 400, redirectUri, holderState);
    }
}
//# sourceMappingURL=openid.error.js.map