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

export class OAuthCallbackError extends HappyViewError {
  readonly params: URLSearchParams;
  readonly state: string | undefined;

  static from(
    err: unknown,
    params: URLSearchParams,
    state?: string,
  ): OAuthCallbackError {
    if (err instanceof OAuthCallbackError) return err;
    const message = err instanceof Error ? err.message : undefined;
    return new OAuthCallbackError(params, message, state, err);
  }

  constructor(
    params: URLSearchParams,
    message?: string,
    state?: string,
    cause?: unknown,
  ) {
    super(
      message ??
        params.get("error_description") ??
        "OAuth callback error",
    );
    this.name = "OAuthCallbackError";
    this.params = params;
    this.state = state;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}
