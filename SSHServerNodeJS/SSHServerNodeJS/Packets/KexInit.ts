import { Packet } from "./Packet";
import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";

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
}
