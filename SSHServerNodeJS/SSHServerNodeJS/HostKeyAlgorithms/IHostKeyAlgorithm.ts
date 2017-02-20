import { IAlgorithm } from "../IAlgorithm";

export interface IHostKeyAlgorithm extends IAlgorithm {
    createKeyAndCertificatesData(): Buffer;
    createSignatureData(hash: Buffer): Buffer;
}
