import { Packet } from "./Packet";
import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";
import * as Exceptions from "../SSHServerException";

export class KexDHReply extends Packet {
    public serverHostKey: Buffer;
    public serverValue: Buffer;
    public signature: Buffer;

    public getPacketType(): PacketType {
        return PacketType.SSH_MSG_KEXDH_REPLY;
    }

    protected internalGetBytes(writer: ByteWriter) {
        // string server public host key and certificates(K_S)
        // mpint f
        // string signature of H
        writer.writeBytes(this.serverHostKey);
        writer.writeMPInt(this.serverValue);
        writer.writeBytes(this.signature);
    }

    public load(reader: ByteReader) {
        // Client never sends this!
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "SSH Client should never send a SSH_MSG_KEXDH_REPLY message");
    }
}
