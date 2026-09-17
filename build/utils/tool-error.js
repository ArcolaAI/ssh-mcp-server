export class ToolError extends Error {
    code;
    retriable;
    constructor(code, message, retriable = false) {
        super(message);
        this.code = code;
        this.retriable = retriable;
        this.name = "ToolError";
    }
}
export function toToolError(error, fallbackCode) {
    if (error instanceof ToolError) {
        return error;
    }
    if (error instanceof Error) {
        return new ToolError(fallbackCode, error.message, false);
    }
    return new ToolError(fallbackCode, String(error), false);
}
