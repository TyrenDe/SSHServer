import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";

export abstract class Packet {
    // https://tools.ietf.org/html/rfc4253#section-6.1
    public static MaxPacketSize: number = 35000;
    public static PacketHeaderSize: number = 5;

    public packetSequence: number = 0;

    public abstract getPacketType(): PacketType;

    public getBytes(): Buffer {
        let writer: ByteWriter = new ByteWriter();

        writer.writePacketType(this.getPacketType());
        this.internalGetBytes(writer);
        return writer.toBuffer();
    }

    public abstract load(reader: ByteReader): void;

    protected abstract internalGetBytes(writer: ByteWriter): void;
}