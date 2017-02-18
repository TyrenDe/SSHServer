import { ICipher } from "./ICipher";

export class TripleDESCBC implements ICipher {
    public getName(): string {
        return "3des-cbc";
    }

    public getBlockSize(): number {
        return 8;
    }

    public getKeySize(): number {
        return 0;
    }

    public encrypt(data: Buffer): Buffer {
        return data;
    }

    public decrypt(data: Buffer): Buffer {
        return data;
    }

    public setKey(key: Buffer, iv: Buffer): void {
    }
}
