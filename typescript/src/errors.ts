/** IdentityKit errors. Verification fails closed. */

export class IdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class InvalidIdentity extends IdentityError {
  field?: string;
  constructor(message: string, field?: string) {
    super(message);
    this.field = field;
  }
}

export class ResolutionError extends IdentityError {}

export class UnsupportedMethod extends ResolutionError {}
