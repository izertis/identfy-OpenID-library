export class OpenIdError extends Error {
  constructor(
    public code: string,
    public message: string,
    public recommendedHttpStatus?: number,
    public redirectUri?: string,
    public holderState?: string,
  ) {
    super();
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
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('invalid_request', message, 400, redirectUri, holderState);
  }
}

export class AccessDenied extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('access_denied', message, 403, redirectUri, holderState);
  }
}

export class InvalidClient extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('invalid_client', message, 401, redirectUri, holderState);
  }
}

export class InvalidGrant extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('invalid_grant', message, 400, redirectUri, holderState);
  }
}

export class UnauthorizedClient extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('unauthorized_client', message, 400, redirectUri, holderState);
  }
}

export class UnsupportedGrantType extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('unsupported_grant_type', message, 400, redirectUri, holderState);
  }
}

export class InvalidScope extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('invalid_scope', message, 400, redirectUri, holderState);
  }
}

export class InvalidToken extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('invalid_token', message, 401, redirectUri, holderState);
  }
}

export class InsufficientScope extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('insufficient_scope', message, 403, redirectUri, holderState);
  }
}

export class InvalidCredentialRequest extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('invalid_credential_request', message, 400, redirectUri, holderState);
  }
}

export class UnsupportedCredentialType extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super(
      'unsupported_credential_type',
      message,
      400,
      redirectUri,
      holderState,
    );
  }
}

export class UnsupportedCredentialFormat extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super(
      'unsupported_credential_format',
      message,
      400,
      redirectUri,
      holderState,
    );
  }
}

export class InvalidProof extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('invalid_proof', message, 400, redirectUri, holderState);
  }
}

export class UnsupportedResponseType extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('unsupported_response_type', message, 400, redirectUri, holderState);
  }
}

export class VpFormatsNotSupported extends OpenIdError {
  constructor(message: string, redirectUri?: string, holderState?: string) {
    super('vp_formats_not_supported', message, 400, redirectUri, holderState);
  }
}
