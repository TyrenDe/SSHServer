import { IMACAlgorithm } from "./IMACAlgorithm";

import crypto = require("crypto");

export class HMACSHA1 implements IMACAlgorithm {
    constructor() {
    }

    public getName(): string {
        return "hmac-sha1";
    }

    public getKeySize(): number {
        // https://tools.ietf.org/html/rfc4253#section-6.4
        // according to this, the KeySize is 20
        return 20;
    }

    public getDigestLength(): number {
        // https://tools.ietf.org/html/rfc4253#section-6.4
        // according to this, the DigestLength is 20
        return 20;
    }

    public setKey(key: Buffer): void {
    }

    public computeHash(packetNumber: number, data: Buffer): Buffer {
        return null;

    }
}
