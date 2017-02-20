import { IAlgorithm } from "../IAlgorithm";

export interface IKexAlgorithm extends IAlgorithm {
    createKeyExchange(): Buffer;
    decryptKeyExchange(keyEx: Buffer): Buffer;
    computeHash(value: Buffer): Buffer;
}
