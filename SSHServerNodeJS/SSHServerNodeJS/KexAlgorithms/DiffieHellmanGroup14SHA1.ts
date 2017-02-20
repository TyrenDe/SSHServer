import { IKexAlgorithm } from "./IKexAlgorithm";

import crypto = require("crypto");

export class DiffieHellmanGroup14SHA1 implements IKexAlgorithm {
    private m_DiffieHellman: crypto.DiffieHellman;

    constructor() {
        this.m_DiffieHellman = crypto.getDiffieHellman("modp14");
        this.m_DiffieHellman.generateKeys();
    }

    public getName(): string {
        return "diffie-hellman-group14-sha1";
    }

    public createKeyExchange(): Buffer {
        return this.m_DiffieHellman.getPublicKey();
    }

    public decryptKeyExchange(keyEx: Buffer): Buffer {
        return this.m_DiffieHellman.computeSecret(keyEx);
    }

    public computeHash(value: Buffer): Buffer {
        let sha1: crypto.Hash = crypto.createHash("SHA1");
        return sha1.update(value).digest();
    }
}
