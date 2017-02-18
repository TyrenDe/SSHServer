import { IAlgorithm } from "../IAlgorithm";

export interface ICipher extends IAlgorithm {
    getBlockSize(): number;
    getKeySize(): number;
    encrypt(data: Buffer): Buffer;
    decrypt(data: Buffer): Buffer;
    setKey(key: Buffer, iv: Buffer): void;
}
