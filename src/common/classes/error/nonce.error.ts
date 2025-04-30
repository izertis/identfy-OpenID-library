export abstract class NonceError extends Error {
  constructor(public nonceId: string) {
    super();
  }
}

export class NonceNotFound extends NonceError {
  constructor(public nonceId: string) {
    super(nonceId);
    this.message = `Nonce ${nonceId} not found`;
  }
}

export class InternalNonceError extends NonceError {
  constructor(public nonceId: string) {
    super(nonceId);
    this.message = `Internal error retrieving nonce ${nonceId}`;
  }
}

export class InvalidNonceStage extends NonceError {
  constructor(
    public nonceId: string,
    expectedStage: string,
    currentStage: string,
  ) {
    super(nonceId);
    this.message = `Nonce ${nonceId} expected stage "${expectedStage}" but "${currentStage}" was found`;
  }
}
