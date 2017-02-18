import { IAlgorithm } from "../IAlgorithm";

export interface IKexAlgorithm extends IAlgorithm {
    createKeyExchange(): string;
    decryptKeyExchange(keyEx: string): string;
    computeHash(value: string): string;
}
