import { Packet } from "./Packet";
import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";
import { DisconnectReason } from "./DisconnectReason";

export class Disconnect extends Packet {
    public reason: DisconnectReason;
    public description: string;
    public language: string = "en";

    public getPacketType(): PacketType {
        return PacketType.SSH_MSG_DISCONNECT;
    }

    protected internalGetBytes(writer: ByteWriter) {
        writer.writeUInt32(<number>this.reason);
        writer.writeString(this.description, "UTF8");
        writer.writeString(this.language);
    }

    public load(reader: ByteReader) {
        this.reason = <DisconnectReason>reader.getUInt32();
        this.description = reader.getString("UTF8");
        if (!reader.isEOF())
            this.language = reader.getString();
    }
}
