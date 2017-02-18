import { IAlgorithm } from "../IAlgorithm";

export interface IHostKeyAlgorithm extends IAlgorithm {
    importKey(keyXml: string): void;
    createKeyAndCertificatesData(): string;
    createSignatureData(hash: string): string;
}
