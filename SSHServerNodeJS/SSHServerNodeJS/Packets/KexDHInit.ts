import { Packet } from "./Packet";
import { PacketType } from "./PacketType";
import { ByteReader } from "../ByteReader";
import { ByteWriter } from "../ByteWriter";
import * as Exceptions from "../SSHServerException";

export class KexDHInit extends Packet {
    public clientValue: Buffer;

    public getPacketType(): PacketType {
        return PacketType.SSH_MSG_KEXDH_INIT;
    }

    protected internalGetBytes(writer: ByteWriter) {
        // Server never sends this
        throw new Exceptions.SSHServerException(
            Exceptions.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "SSH Server should never send a SSH_MSG_KEXDH_INIT message");
    }

    public load(reader: ByteReader) {
        this.clientValue = reader.getMPInt();
    }
}
