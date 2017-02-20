import { IMACAlgorithm } from "./IMACAlgorithm";
import * as Exceptions from "../SSHServerException";
import { ByteWriter } from "../ByteWriter";

import crypto = require("crypto");

export class HMACSHA1 implements IMACAlgorithm {
    private m_MHAC: crypto.Hmac;
    private m_Key: Buffer;

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
        this.m_Key = key;
    }

    public computeHash(packetNumber: number, data: Buffer): Buffer {
        if (this.m_Key === null) {
            throw new Exceptions.SSHServerException(
                Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                "SetKey must be called before attempting to ComputeHash.");
        }

        let writer: ByteWriter = new ByteWriter();
        writer.writeUInt32(packetNumber);
        writer.writeRawBytes(data);

        let hmac: crypto.Hmac = crypto.createHmac("sha1", this.m_Key);
        hmac.update(writer.toBuffer());
        return hmac.digest();
    }
}
