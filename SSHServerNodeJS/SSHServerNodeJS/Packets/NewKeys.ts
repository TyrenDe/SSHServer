import { Packet } from "./Packet";
import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";

export class NewKeys extends Packet {
    public clientValue: Buffer;

    public getPacketType(): PacketType {
        return PacketType.SSH_MSG_NEWKEYS;
    }

    protected internalGetBytes(writer: ByteWriter) {
        // no data, nothing to write
    }

    public load(reader: ByteReader) {
        // no data, nothing to load
    }
}
