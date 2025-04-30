export class Result {
    ok;
    error;
    constructor(ok, error) {
        this.ok = ok;
        this.error = error;
    }
    static Ok(data) {
        return new Result(data, undefined);
    }
    static Err(data) {
        return new Result(undefined, data);
    }
    isError() {
        return this.error !== undefined;
    }
    isOk() {
        return this.ok !== undefined;
    }
    unwrap() {
        if (this.isOk()) {
            return this.ok;
        }
        throw new Error('Unwrap of error value');
    }
    unwrapError() {
        if (this.isError()) {
            return this.error;
        }
        throw new Error('Unwrap of non error value');
    }
    map(handler) {
        if (this.isError()) {
            return Result.Err(this.error);
        }
        return Result.Ok(handler(this.ok));
    }
    consume() {
        if (this.isOk()) {
            return this.ok;
        }
        throw this.error;
    }
}
//# sourceMappingURL=result.js.map