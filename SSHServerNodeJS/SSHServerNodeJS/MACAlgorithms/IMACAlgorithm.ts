import { IAlgorithm } from "../IAlgorithm";

export interface IMACAlgorithm extends IAlgorithm {
    getKeySize(): number;
    getDigestLength(): number;
    setKey(key: Buffer): void;
    computeHash(packetNumber: number, data: Buffer): Buffer;
}
