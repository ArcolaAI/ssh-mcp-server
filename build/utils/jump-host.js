export function parseJumpSpec(spec, defaultUsername) {
    const raw = spec.trim();
    if (raw.length === 0) {
        throw new Error("Jump host is empty");
    }
    if (raw.includes(",")) {
        throw new Error(`Jump host '${raw}' is a chain; only one hop is supported`);
    }
    let username = defaultUsername;
    let rest = raw;
    const at = raw.lastIndexOf("@");
    if (at !== -1) {
        username = raw.slice(0, at);
        rest = raw.slice(at + 1);
        if (username.length === 0) {
            throw new Error(`Jump host '${raw}' has an empty user`);
        }
    }
    let host = rest;
    let port = 22;
    const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(rest);
    if (bracketed) {
        host = bracketed[1];
        if (bracketed[2] !== undefined) {
            port = Number.parseInt(bracketed[2], 10);
        }
    }
    else {
        const colon = rest.lastIndexOf(":");
        if (colon !== -1) {
            if (rest.indexOf(":") !== colon) {
                throw new Error(`Jump host '${raw}' looks like a bare IPv6 address; write it as [addr]:port`);
            }
            host = rest.slice(0, colon);
            const portText = rest.slice(colon + 1);
            if (!/^\d+$/.test(portText)) {
                throw new Error(`Jump host '${raw}' has an invalid port`);
            }
            port = Number.parseInt(portText, 10);
        }
    }
    if (host.length === 0) {
        throw new Error(`Jump host '${raw}' has an empty host`);
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`Jump host '${raw}' has an invalid port`);
    }
    return { username, host, port };
}
