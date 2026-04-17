export class HappyViewError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HappyViewError";
  }
}

export class ApiError extends HappyViewError {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

export class AuthenticationError extends HappyViewError {
  readonly status: number;

  constructor(message: string, status: number = 401) {
    super(message);
    this.name = "AuthenticationError";
    this.status = status;
  }
}

export class InvalidStateError extends HappyViewError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidStateError";
  }
}

export class TokenExchangeError extends HappyViewError {
  readonly status: number;
  readonly body: string;

  constructor(message: string, status: number, body: string) {
    super(message);
    this.name = "TokenExchangeError";
    this.status = status;
    this.body = body;
  }
}

export class ResolutionError extends HappyViewError {
  constructor(message: string) {
    super(message);
    this.name = "ResolutionError";
  }
}
