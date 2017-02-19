import { Packet } from "./Packet";
import { Server } from "../Server";
import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";

import { IKexAlgorithm } from "../KexAlgorithms/IKexAlgorithm";
import { DiffieHellmanGroup14SHA1 } from "../KexAlgorithms/DiffieHellmanGroup14SHA1";

import { IHostKeyAlgorithm } from "../HostKeyAlgorithms/IHostKeyAlgorithm";
import { SSHRSA } from "../HostKeyAlgorithms/SSHRSA";

import { ICipher } from "../Ciphers/ICipher";
import { TripleDESCBC } from "../Ciphers/TripleDESCBC";

import { IMACAlgorithm } from "../MACAlgorithms/IMACAlgorithm";
import { HMACSHA1 } from "../MACAlgorithms/HMACSHA1";

import { ICompression } from "../Compressions/ICompression";
import { NoCompression } from "../Compressions/NoCompression";

import * as Exceptions from "../SSHServerException";

import crypto = require('crypto');

export class KexInit extends Packet {
    public getPacketType(): PacketType {
        return PacketType.SSH_MSG_KEXINIT;
    }

    public cookie: Buffer = crypto.randomBytes(16);
    public kexAlgorithms: Array<string> = new Array<string>();
    public serverHostKeyAlgorithms : Array<string> = new Array<string>();
    public encryptionAlgorithmsClientToServer : Array<string> = new Array<string>();
    public encryptionAlgorithmsServerToClient : Array<string> = new Array<string>();
    public macAlgorithmsClientToServer : Array<string> = new Array<string>();
    public macAlgorithmsServerToClient : Array<string> = new Array<string>();
    public compressionAlgorithmsClientToServer : Array<string> = new Array<string>();
    public compressionAlgorithmsServerToClient : Array<string> = new Array<string>();
    public languagesClientToServer : Array<string> = new Array<string>();
    public languagesServerToClient: Array<string> = new Array<string>();
    public firstKexPacketFollows: boolean = false;

    protected internalGetBytes(writer: ByteWriter) {
        writer.writeRawBytes(this.cookie);
        writer.writeStringList(this.kexAlgorithms);
        writer.writeStringList(this.serverHostKeyAlgorithms);
        writer.writeStringList(this.encryptionAlgorithmsClientToServer);
        writer.writeStringList(this.encryptionAlgorithmsServerToClient);
        writer.writeStringList(this.macAlgorithmsClientToServer);
        writer.writeStringList(this.macAlgorithmsServerToClient);
        writer.writeStringList(this.compressionAlgorithmsClientToServer);
        writer.writeStringList(this.compressionAlgorithmsServerToClient);
        writer.writeStringList(this.languagesClientToServer);
        writer.writeStringList(this.languagesServerToClient);
        writer.writeByte(this.firstKexPacketFollows ? 0x01 : 0x00);
        writer.writeUInt32(0);
    }

    public load(reader: ByteReader) {
        this.cookie = reader.getBytes(16);
        this.kexAlgorithms = reader.getNameList();
        this.serverHostKeyAlgorithms = reader.getNameList();
        this.encryptionAlgorithmsClientToServer = reader.getNameList();
        this.encryptionAlgorithmsServerToClient = reader.getNameList();
        this.macAlgorithmsClientToServer = reader.getNameList();
        this.macAlgorithmsServerToClient = reader.getNameList();
        this.compressionAlgorithmsClientToServer = reader.getNameList();
        this.compressionAlgorithmsServerToClient = reader.getNameList();
        this.languagesClientToServer = reader.getNameList();
        this.languagesServerToClient = reader.getNameList();
        this.firstKexPacketFollows = reader.getBoolean();

        // uint32       0 (reserved for future extension)
        reader.getUInt32();
    }

    public pickKexAlgorithm(): IKexAlgorithm {
        for (let algo of this.kexAlgorithms) {
            if (Server.SupportedKexAlgorithms.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "diffie-hellman-group14-sha1":
                        return new DiffieHellmanGroup14SHA1();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Kex Algorithm");
    }

    public pickHostKeyAlgorithm(): IHostKeyAlgorithm {
        for (let algo of this.serverHostKeyAlgorithms) {
            if (Server.SupportedHostKeyAlgorithms.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "ssh-rsa":
                        return new SSHRSA();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Host Key Algorithm");
    }

    public pickCipherClientToServer(): ICipher {
        for (let algo of this.encryptionAlgorithmsClientToServer) {
            if (Server.SupportedCiphers.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "3des-cbc":
                        return new TripleDESCBC();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Client-To-Server Cipher Algorithm");
    }

    public pickCipherServerToClient(): ICipher {
        for (let algo of this.encryptionAlgorithmsServerToClient) {
            if (Server.SupportedCiphers.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "3des-cbc":
                        return new TripleDESCBC();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Server-To-Client Cipher Algorithm");
    }

    public pickMACAlgorithmClientToServer(): IMACAlgorithm {
        for (let algo of this.macAlgorithmsClientToServer) {
            if (Server.SupportedMACAlgorithms.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "hmac-sha1":
                        return new HMACSHA1();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Client-To-Server MAC Algorithm");
    }

    public pickMACAlgorithmServerToClient(): IMACAlgorithm {
        for (let algo of this.macAlgorithmsServerToClient) {
            if (Server.SupportedMACAlgorithms.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "hmac-sha1":
                        return new HMACSHA1();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Server-To-Client MAC Algorithm");
    }

    public pickCompressionAlgorithmClientToServer(): ICompression {
        for (let algo of this.compressionAlgorithmsClientToServer) {
            if (Server.SupportedCompressions.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "none":
                        return new NoCompression();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Client-To-Server Compression Algorithm");
    }

    public pickCompressionAlgorithmServerToClient(): ICompression {
        for (let algo of this.compressionAlgorithmsServerToClient) {
            if (Server.SupportedCompressions.find(
                (value: string, index: number, obj: Array<string>): boolean => {
                    return (value === algo);
                })) {

                switch (algo) {
                    case "none":
                        return new NoCompression();
                }
            }
        }

        // If no algorithm satisfying all these conditions can be found, the
        // connection fails, and both sides MUST disconnect.
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Could not find a shared Server-To-Client Compresion Algorithm");
    }
}
