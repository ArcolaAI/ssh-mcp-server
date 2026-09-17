/**
 * OpenSSH known_hosts support for host-key verification.
 *
 * ssh2 performs NO host-key verification unless a `hostVerifier` is supplied,
 * so without this module every connection accepts whatever host key the far
 * end offers. The verifier built here checks the offered key (the raw SSH wire
 * blob ssh2 hands to `hostVerifier` when `hostHash` is unset) against the same
 * trust store the OpenSSH client uses, and is fail-closed: an unknown host, a
 * key that matches no entry, a `@revoked` entry, or an unreadable file all
 * refuse the connection.
 *
 * Supported known_hosts syntax (sshd(8) SSH_KNOWN_HOSTS FILE FORMAT):
 *   - comma-separated host patterns, `*` / `?` wildcards, `!` negation
 *   - `[host]:port` for non-default ports
 *   - hashed hostnames `|1|<salt>|<hmac-sha1>`
 *   - `@revoked` marker (refuses); `@cert-authority` lines are ignored because
 *     certificate host keys are not verified by this module
 *
 * The module never writes to known_hosts. Trust-on-first-use is a human
 * decision made once with the OpenSSH client, not something an automated tool
 * should do on the operator's behalf.
 */
import fs from "fs";
import os from "os";
import path from "path";
import { createHmac } from "crypto";
const DEFAULT_PORT = 22;
/** ssh2 `algorithms.serverHostKey` names that can present a known_hosts key of the given type. */
const HOST_KEY_ALGORITHMS = {
    "ssh-ed25519": ["ssh-ed25519"],
    "ecdsa-sha2-nistp256": ["ecdsa-sha2-nistp256"],
    "ecdsa-sha2-nistp384": ["ecdsa-sha2-nistp384"],
    "ecdsa-sha2-nistp521": ["ecdsa-sha2-nistp521"],
    "ssh-rsa": ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
    "ssh-dss": ["ssh-dss"],
};
/** Preference order when more than one key type is known for a host. */
const KEY_TYPE_PREFERENCE = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "ssh-dss",
];
export function defaultKnownHostsPath() {
    return path.join(os.homedir(), ".ssh", "known_hosts");
}
/**
 * Parse a known_hosts file body. Malformed lines are skipped, not fatal, to
 * match OpenSSH, which tolerates them and simply cannot match against them.
 */
export function parseKnownHosts(content) {
    const entries = [];
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i].trim();
        if (raw.length === 0 || raw.startsWith("#")) {
            continue;
        }
        const fields = raw.split(/\s+/);
        let marker;
        if (fields[0].startsWith("@")) {
            const m = fields.shift().slice(1);
            if (m === "revoked" || m === "cert-authority") {
                marker = m;
            }
            else {
                continue; // unknown marker - cannot interpret, cannot match
            }
        }
        if (fields.length < 3) {
            continue;
        }
        const [hostField, keyType, keyB64] = fields;
        let key;
        try {
            key = Buffer.from(keyB64, "base64");
        }
        catch {
            continue;
        }
        if (key.length === 0 || !isWireBlobOfType(key, keyType)) {
            continue;
        }
        entries.push({
            marker,
            patterns: hostField.split(","),
            keyType,
            key,
            lineNumber: i + 1,
        });
    }
    return entries;
}
/** The wire blob begins with a length-prefixed key-type string; require it to agree with the declared type. */
function isWireBlobOfType(blob, keyType) {
    if (blob.length < 4) {
        return false;
    }
    const len = blob.readUInt32BE(0);
    if (len <= 0 || len > blob.length - 4) {
        return false;
    }
    return blob.subarray(4, 4 + len).toString("utf8") === keyType;
}
/** The name OpenSSH looks up: bare host on port 22, `[host]:port` otherwise. */
export function knownHostsLookupName(host, port) {
    return port === DEFAULT_PORT ? host : `[${host}]:${port}`;
}
function globToRegExp(pattern) {
    const escaped = pattern
        .replace(/[.+^${}()|\\/]/g, "\\$&")
        .replace(/\[/g, "\\[")
        .replace(/\]/g, "\\]")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".");
    return new RegExp(`^${escaped}$`, "i");
}
function hashedPatternMatches(pattern, name) {
    // |1|<base64 salt>|<base64 hmac-sha1(salt, name)>
    const parts = pattern.split("|");
    if (parts.length !== 4 || parts[1] !== "1") {
        return false;
    }
    try {
        const salt = Buffer.from(parts[2], "base64");
        const expected = Buffer.from(parts[3], "base64");
        const actual = createHmac("sha1", salt).update(name).digest();
        return (actual.length === expected.length && actual.equals(expected));
    }
    catch {
        return false;
    }
}
/**
 * Does this entry's host field match the lookup name? Implements OpenSSH
 * semantics: any positive pattern must match and no negated pattern may.
 */
export function entryMatchesHost(entry, lookupName) {
    let positive = false;
    for (const pattern of entry.patterns) {
        if (pattern.length === 0) {
            continue;
        }
        if (pattern.startsWith("|1|")) {
            if (hashedPatternMatches(pattern, lookupName)) {
                positive = true;
            }
            continue;
        }
        const negated = pattern.startsWith("!");
        const body = negated ? pattern.slice(1) : pattern;
        const matched = body.includes("*") || body.includes("?")
            ? globToRegExp(body).test(lookupName)
            : body.toLowerCase() === lookupName.toLowerCase();
        if (matched && negated) {
            return false;
        }
        if (matched) {
            positive = true;
        }
    }
    return positive;
}
export function findHostEntries(entries, host, port) {
    const name = knownHostsLookupName(host, port);
    return entries.filter((e) => entryMatchesHost(e, name));
}
/**
 * Compare an offered host key (raw wire blob, as ssh2 passes it to
 * `hostVerifier` without `hostHash`) against the entries that match the host.
 */
export function verifyOfferedKey(hostEntries, offeredKey) {
    const offeredType = wireBlobType(offeredKey);
    const usable = hostEntries.filter((e) => e.marker !== "cert-authority");
    if (usable.length === 0) {
        return {
            ok: false,
            reason: "unknown-host",
            detail: "no known_hosts entry for this host",
        };
    }
    for (const entry of usable) {
        if (entry.marker === "revoked" && entry.key.equals(offeredKey)) {
            return {
                ok: false,
                reason: "revoked",
                detail: `offered ${entry.keyType} key is marked @revoked (known_hosts line ${entry.lineNumber})`,
            };
        }
    }
    for (const entry of usable) {
        if (entry.marker === undefined && entry.key.equals(offeredKey)) {
            return { ok: true, keyType: entry.keyType, lineNumber: entry.lineNumber };
        }
    }
    const knownTypes = Array.from(new Set(usable.filter((e) => e.marker === undefined).map((e) => e.keyType)));
    const sameType = knownTypes.includes(offeredType ?? "");
    return {
        ok: false,
        reason: "mismatch",
        detail: sameType
            ? `offered ${offeredType} key does not match the known_hosts ${offeredType} key for this host - HOST KEY HAS CHANGED OR THE HOST IS BEING IMPERSONATED`
            : `offered ${offeredType ?? "unknown-type"} key; known_hosts holds only [${knownTypes.join(", ")}] for this host`,
    };
}
function wireBlobType(blob) {
    if (blob.length < 4) {
        return undefined;
    }
    const len = blob.readUInt32BE(0);
    if (len <= 0 || len > blob.length - 4) {
        return undefined;
    }
    return blob.subarray(4, 4 + len).toString("utf8");
}
/**
 * ssh2 `algorithms.serverHostKey` list restricted to the key types known_hosts
 * holds for this host, most-preferred first. Offering only known types means
 * a host that has several key types can never negotiate one we cannot verify.
 */
export function serverHostKeyAlgorithmsFor(hostEntries) {
    const types = new Set(hostEntries.filter((e) => e.marker === undefined).map((e) => e.keyType));
    const ordered = KEY_TYPE_PREFERENCE.filter((t) => types.has(t));
    const algorithms = [];
    for (const t of ordered) {
        for (const a of HOST_KEY_ALGORITHMS[t] ?? []) {
            if (!algorithms.includes(a)) {
                algorithms.push(a);
            }
        }
    }
    return algorithms;
}
/** Read and parse a known_hosts file. Throws (fail-closed) if it cannot be read. */
export function loadKnownHosts(filePath) {
    const resolved = filePath ?? defaultKnownHostsPath();
    const content = fs.readFileSync(resolved, "utf8");
    return { path: resolved, entries: parseKnownHosts(content) };
}
