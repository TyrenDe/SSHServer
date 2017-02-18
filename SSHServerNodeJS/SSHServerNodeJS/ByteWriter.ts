import { PacketType } from "./Packets/PacketType";

export class ByteWriter {
    private m_Data: Array<number> = new Array<number>();

    public writePacketType(packetType: PacketType): void {
        this.m_Data.push(packetType);
    }

    public writeBytes(value: Buffer): void {
        this.writeUInt32(value.length);
        this.writeRawBytes(value);
    }

    public writeString(value: string, encoding?: string): void {
        if (encoding == null) {
            encoding = "ASCII";
        }

        let buffer: Buffer = new Buffer(value, encoding);

        this.writeUInt32(buffer.length);
        this.writeRawBytes(buffer);
    }

    public writeStringList(list: Array<string>): void {
        this.writeString(list.join(","));
    }

    public writeUInt32(value: number): void {
        let buffer: Buffer = new Buffer(4);
        buffer.writeInt32BE(value, 0);
        this.writeRawBytes(buffer);
    }

    public writeMPInt(value: Buffer): void {
        if ((value.length === 1) && (value[0] === 0)) {
            this.writeUInt32(0);
            return;
        }

        let length: number = value.length;
        if ((value[0] & 0x80) !== 0) {
            this.writeUInt32(length + 1);
            this.writeByte(0x00);
        } else {
            this.writeUInt32(length);
        }

        this.writeRawBytes(value);
    }

    public writeRawBytes(value: Buffer): void {
        for (let v of value) {
            this.m_Data.push(v);
        }
    }

    public writeByte(value: number): void {
        this.m_Data.push(value);
    }

    public toBuffer(): Buffer {
        return Buffer.from(this.m_Data);
    }
}
