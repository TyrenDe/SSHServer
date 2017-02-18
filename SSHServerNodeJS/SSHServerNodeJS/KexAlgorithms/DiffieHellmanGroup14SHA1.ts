import { IKexAlgorithm } from "./IKexAlgorithm";

import crypto = require("crypto");

export class DiffieHellmanGroup14SHA1 implements IKexAlgorithm {
    private m_DiffieHellman: crypto.DiffieHellman;
    private m_SHA1: crypto.Hash;

    constructor() {
        this.m_DiffieHellman = crypto.getDiffieHellman("modp14");
        this.m_DiffieHellman.generateKeys();

        this.m_SHA1 = crypto.createHash("SHA1");
    }

    public getName(): string {
        return "diffie-hellman-group14-sha1";
    }

    public createKeyExchange(): string {
        return this.m_DiffieHellman.getPublicKey("hex");
    }

    public decryptKeyExchange(keyEx: string): string {
        return this.m_DiffieHellman.computeSecret(keyEx, "hex", "hex");
    }

    public computeHash(value: string): string {
        this.m_SHA1.update(value);
        return this.m_SHA1.digest("hex");
    }
}
