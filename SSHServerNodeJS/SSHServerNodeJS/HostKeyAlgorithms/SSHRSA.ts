import { IHostKeyAlgorithm } from "./IHostKeyAlgorithm";

import crypto = require("crypto");

export class SSHRSA implements IHostKeyAlgorithm {
    private m_Modulus: string;
    private m_Exponent: string;

    constructor() {
        // this.m_RSA = crypto.createSign("RSA");
    }

    public getName(): string {
        return "ssh-rsa";
    }

    public importKey(m: string): void {
    }

    public createKeyAndCertificatesData(): string {
        return "";
    }

    public createSignatureData(hash: string): string {
        return "";
    }
}
