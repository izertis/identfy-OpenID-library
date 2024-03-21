export class OpenIdError extends Error {
  constructor(
    public code: string,
    public message: string,
    public recomiendedHttpStatus?: number
  ) {
    super();
  }

  toRfcSpecification() {
    return {
      status: this.recomiendedHttpStatus,
      error: {
        code: this.code,
        erro_description: this.message,
      }
    }
  }
}

export class InvalidRequest extends OpenIdError {
  constructor(message: string) {
    super("invalid_request", message, 400);
  }
}

export class AccessDenied extends OpenIdError {
  constructor(message: string) {
    super("access_denied", message);
  }
}

export class InvalidClient extends OpenIdError {
  constructor(message: string) {
    super("invalid_client", message, 401);
  }
}

export class InvalidGrant extends OpenIdError {
  constructor(message: string) {
    super("invalid_grant", message, 400);
  }
}

export class UnauthorizedClient extends OpenIdError {
  constructor(message: string) {
    super("unauthorized_client", message, 400);
  }
}

export class UnsupportedGrantType extends OpenIdError {
  constructor(message: string) {
    super("unsupported_grant_type", message, 400);
  }
}

export class InvalidScope extends OpenIdError {
  constructor(message: string) {
    super("invalid_scope", message, 400);
  }
}

export class InvalidToken extends OpenIdError {
  constructor(message: string) {
    super("invalid_token", message, 401);
  }
}

export class InsufficientScope extends OpenIdError {
  constructor(message: string) {
    super("insufficient_scope", message, 403);
  }
}

export class InvalidCredentialRequest extends OpenIdError {
  constructor(message: string) {
    super("invalid_credential_request", message, 400);
  }
}

export class UnsupportedCredentialType extends OpenIdError {
  constructor(message: string) {
    super("unsupported_credential_type", message, 400);
  }
}

export class UnsupportedCredentialFormat extends OpenIdError {
  constructor(message: string) {
    super("unsupported_credential_format", message, 400);
  }
}

export class InvalidProof extends OpenIdError {
  constructor(message: string) {
    super("invalid_proof", message, 400);
  }
}

export class UnsupportedResponseType extends OpenIdError {
  constructor(message: string) {
    super("unsupported_response_type", message);
  }
}

export class VpFormatsNotSupported extends OpenIdError {
  constructor(message: string) {
    super("vp_formats_not_supported", message);
  }
}
