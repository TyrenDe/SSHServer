import { ICipher } from "./ICipher";

import crypto = require("crypto");

export class TripleDESCBC implements ICipher {
    private m_Encryptor: crypto.Cipher;
    private m_Decryptor: crypto.Decipher;

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
        return this.m_Encryptor.update(data);
    }

    public decrypt(data: Buffer): Buffer {
        return this.m_Decryptor.update(data);
    }

    public setKey(key: Buffer, iv: Buffer): void {
        this.m_Encryptor = crypto.createCipheriv("DES-EDE3-CBC", key, iv);
        this.m_Encryptor.setAutoPadding(false);

        this.m_Decryptor = crypto.createDecipheriv("DES-EDE3-CBC", key, iv);
        this.m_Decryptor.setAutoPadding(false);
    }
}
