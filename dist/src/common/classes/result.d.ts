export declare class Result<S, E extends Error | unknown> {
    protected ok: S | undefined;
    protected error: E | undefined;
    protected constructor(ok: S | undefined, error: E | undefined);
    static Ok<S>(data: S): Result<S, any>;
    static Err<E>(data: E): Result<any, E>;
    isError(): boolean;
    isOk(): boolean;
    unwrap(): S;
    unwrapError(): E;
    map<N>(handler: (content: S) => N): Result<N, E>;
    consume(): S;
}
