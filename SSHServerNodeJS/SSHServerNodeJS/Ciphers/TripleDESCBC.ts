import { ICipher } from "./ICipher";

import crypto = require("crypto");

export class TripleDESCBC implements ICipher {
    private m_3DES: crypto.Cipher;

    public getName(): string {
        return "3des-cbc";
    }

    public getBlockSize(): number {
        return 8;
    }

    public getKeySize(): number {
        return 24;
    }

    public encrypt(data: Buffer): Buffer {
        return this.m_3DES.update(data);
    }

    public decrypt(data: Buffer): Buffer {
        return this.m_3DES.update(data);
    }

    public setKey(key: Buffer, iv: Buffer): void {
        this.m_3DES = crypto.createCipheriv("des3", key, iv);
    }
}
