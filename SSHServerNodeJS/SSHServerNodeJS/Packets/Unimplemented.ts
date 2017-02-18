import { Packet } from "./Packet";
import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";

export class Unimplemented extends Packet {
    public rejectedPacketNumber: number;

    public getPacketType(): PacketType {
        return PacketType.SSH_MSG_UNIMPLEMENTED;
    }

    protected internalGetBytes(writer: ByteWriter) {
        writer.writeUInt32(this.rejectedPacketNumber);
    }

    public load(reader: ByteReader) {
        this.rejectedPacketNumber = reader.getUInt32();
    }
}
