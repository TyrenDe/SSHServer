import { IAlgorithm } from "../IAlgorithm";

export interface ICompression extends IAlgorithm {
    compress(data: Buffer): Buffer;
    decompress(data: Buffer): Buffer;
}
