import { IHostKeyAlgorithm } from "./IHostKeyAlgorithm";
import { ByteWriter } from "../ByteWriter";

import crypto = require("crypto");

export class SSHRSA implements IHostKeyAlgorithm {
    private m_PEM: string;
    private m_Modulus: Buffer;
    private m_Exponent: Buffer;

    constructor(pem: string, m: Buffer, e: Buffer) {
        this.m_PEM = pem;
        this.m_Modulus = m;
        this.m_Exponent = e;
    }

    public getName(): string {
        return "ssh-rsa";
    }

    public createKeyAndCertificatesData(): Buffer {
        // The "ssh-rsa" key format has the following specific encoding:
        //      string    "ssh-rsa"
        //      mpint e
        //      mpint n
        let writer: ByteWriter = new ByteWriter();
        writer.writeString(this.getName());
        writer.writeMPInt(this.m_Exponent);
        writer.writeMPInt(this.m_Modulus);
        return writer.toBuffer();
    }

    public createSignatureData(hash: Buffer): Buffer {
        let rsa: crypto.Signer = crypto.createSign("RSA-SHA1");
        let signBuffer: Buffer = rsa.update(hash).sign(this.m_PEM);

        let writer: ByteWriter = new ByteWriter();
        writer.writeString(this.getName());
        writer.writeBytes(signBuffer);
        return writer.toBuffer();
    }
}
