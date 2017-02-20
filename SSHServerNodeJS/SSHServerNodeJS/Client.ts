import { SSHLogger } from "./SSHLogger";
import { Server } from "./Server";
import { ByteReader } from "./ByteReader";
import { ByteWriter } from "./ByteWriter";
import { ExchangeContext } from "./ExchangeContext";
import * as Packets from "./Packets/PacketType";
import * as Exceptions from "./SSHServerException";
import { IKexAlgorithm } from "./KexAlgorithms/IKexAlgorithm";

import net = require("net");
import util = require("util");
import crypto = require("crypto");

export class Client {
    private m_Socket: net.Socket;
    private m_LastBytesRead: number = 0;

    private m_HasCompletedProtocolVersionExchange: boolean = false;
    private m_ProtocolVersionExchange: string = "";

    private m_KexInitServerToClient: Packets.KexInit = new Packets.KexInit();
    private m_KexInitClientToServer: Packets.KexInit = null;
    private m_SessionId: Buffer = null;

    private m_CurrentSentPacketNumber: number = 0;
    private m_CurrentReceivedPacketNumber: number = 0;

    private m_TotalBytesTransferred: number = 0;
    private m_KeyTimeout: NodeJS.Timer = null;

    private m_ActiveExchangeContext: ExchangeContext = new ExchangeContext();
    private m_PendingExchangeContext: ExchangeContext = new ExchangeContext();

    constructor(socket: net.Socket) {
        this.m_Socket = socket;

        this.resetKeyTimer();

        this.m_KexInitServerToClient.kexAlgorithms = Server.SupportedKexAlgorithms;
        this.m_KexInitServerToClient.serverHostKeyAlgorithms = Server.SupportedHostKeyAlgorithms;
        this.m_KexInitServerToClient.encryptionAlgorithmsClientToServer = Server.SupportedCiphers;
        this.m_KexInitServerToClient.encryptionAlgorithmsServerToClient = Server.SupportedCiphers;
        this.m_KexInitServerToClient.macAlgorithmsClientToServer = Server.SupportedMACAlgorithms;
        this.m_KexInitServerToClient.macAlgorithmsServerToClient = Server.SupportedMACAlgorithms;
        this.m_KexInitServerToClient.compressionAlgorithmsClientToServer = Server.SupportedCompressions;
        this.m_KexInitServerToClient.compressionAlgorithmsServerToClient = Server.SupportedCompressions;
        this.m_KexInitServerToClient.firstKexPacketFollows = false;

        this.m_Socket.setNoDelay(true);

        this.m_Socket.on("close", this.closeReceived.bind(this));

        // 4.2.Protocol Version Exchange - https://tools.ietf.org/html/rfc4253#section-4.2
        this.sendString(util.format("%s\r\n", Server.ProtocolVersionExchange));

        // 7.1.  Algorithm Negotiation - https://tools.ietf.org/html/rfc4253#section-7.1
        this.sendPacket(this.m_KexInitServerToClient);
    }

    public getIsConnected(): boolean {
        return (this.m_Socket != null);
    }

    public poll(): void {
        if (!this.getIsConnected()) {
            return;
        }

        if (this.getIsDataAvailable()) {
            if (!this.m_HasCompletedProtocolVersionExchange) {
                // wait for CRLF
                try {
                    this.readProtocolVersionExchange();
                    if (this.m_HasCompletedProtocolVersionExchange) {
                        SSHLogger.logDebug(util.format("Received ProtocolVersionExchange: %s", this.m_ProtocolVersionExchange));
                        this.validateProtocolVersionExchange();
                    }
                } catch (ex) {
                    SSHLogger.logError(ex);
                    this.disconnect(
                        Exceptions.DisconnectReason.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                        "Failed to get the protocol version exchange.");
                    return;
                }
            }

            if (this.m_HasCompletedProtocolVersionExchange) {
                try {
                    let packet: Packets.Packet = this.readPacket();
                    while (packet != null) {
                        this.handlePacket(packet);
                        packet = this.readPacket();
                    }

                    this.considerReExchange();
                } catch (ex) {
                    if (ex instanceof Exceptions.SSHServerException) {
                        let serverEx: Exceptions.SSHServerException = <Exceptions.SSHServerException>ex;
                        SSHLogger.logError(ex);
                        this.disconnect(serverEx.reason, serverEx.message);
                        return;
                    } else {
                        SSHLogger.logError(ex);
                        this.disconnect(Exceptions.DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, ex.message);
                        return;
                    }
                }
            }
        }
    }

    public sendString(message: string): void {
        if (!this.getIsConnected()) {
            return;
        }

        SSHLogger.logDebug(util.format("Sending raw string: %s", message.trim()));
        this.m_Socket.write(message, "UTF8");
    }

    public sendPacket(packet: Packets.Packet): void {
        packet.packetSequence = this.m_CurrentSentPacketNumber;
        this.m_CurrentSentPacketNumber += 1;

        let payload: Buffer = this.m_ActiveExchangeContext.compressionServerToClient.compress(packet.getBytes());

        let blockSize: number = this.m_ActiveExchangeContext.cipherServerToClient.getBlockSize();

        let paddingLength: number = blockSize - (payload.length + 5) % blockSize;
        if (paddingLength < 4) {
            paddingLength += blockSize;
        }

        let padding: Buffer = crypto.randomBytes(paddingLength);
        let packetLength: number = payload.length + paddingLength + 1;

        let writer: ByteWriter = new ByteWriter();
        writer.writeUInt32(packetLength);
        writer.writeByte(paddingLength);
        writer.writeRawBytes(payload);
        writer.writeRawBytes(padding);

        payload = writer.toBuffer();

        let encryptedPayload: Buffer = this.m_ActiveExchangeContext.cipherServerToClient.encrypt(payload);
        if (this.m_ActiveExchangeContext.macAlgorithmServerToClient != null) {
            let mac: Buffer = this.m_ActiveExchangeContext.macAlgorithmServerToClient.computeHash(packet.packetSequence, payload);
            encryptedPayload = Buffer.concat([encryptedPayload, mac]);
        }

        this.sendRaw(payload);
        this.considerReExchange();
    }

    public disconnect(reason: Exceptions.DisconnectReason, message: string): void {
        if (this.m_Socket != null) {
            SSHLogger.logInfo(util.format(
                "Disconnected from: %s - %s - %s",
                this.m_Socket.remoteAddress,
                Exceptions.DisconnectReason[reason],
                message));

            if (reason !== Exceptions.DisconnectReason.None) {
                try {
                    let disconnect: Packets.Disconnect = new Packets.Disconnect();
                    disconnect.reason = reason;
                    disconnect.description = message;
                    this.sendPacket(disconnect);
                } catch (ex) { }
            }

            try {
                this.m_Socket.destroy();
            } catch (ex) { }
            this.m_Socket = null;
        }
    }

    private handlePacket(packet: Packets.Packet): void {
        switch (packet.getPacketType()) {
            case Packets.PacketType.SSH_MSG_KEXINIT:
                this.handleKexInit(<Packets.KexInit>packet);
                break;
            case Packets.PacketType.SSH_MSG_KEXDH_INIT:
                this.handleKexDHInit(<Packets.KexDHInit>packet);
                break;
            case Packets.PacketType.SSH_MSG_NEWKEYS:
                this.handleNewKeys(<Packets.NewKeys>packet);
                break;
            case Packets.PacketType.SSH_MSG_DISCONNECT:
                this.handleDisconnect(<Packets.Disconnect>packet);
                break;
            default:
                SSHLogger.logWarning(util.format("Unhandled packet type: %s", packet.getPacketType()));
                let unimplemented: Packets.Unimplemented = new Packets.Unimplemented();
                unimplemented.rejectedPacketNumber = packet.packetSequence;
                this.sendPacket(unimplemented);
                break;
        }
    }

    private handleKexInit(packet: Packets.KexInit): void {
        SSHLogger.logDebug("Received KexInit");

        if (this.m_PendingExchangeContext === null) {
            SSHLogger.logDebug("Trigger re-exchange from client");
            this.m_PendingExchangeContext = new ExchangeContext();
            this.sendPacket(this.m_KexInitServerToClient);
        }

        this.m_KexInitClientToServer = packet;

        this.m_PendingExchangeContext.kexAlgorithm = packet.pickKexAlgorithm();
        this.m_PendingExchangeContext.hostKeyAlgorithm = packet.pickHostKeyAlgorithm();
        this.m_PendingExchangeContext.cipherClientToServer = packet.pickCipherClientToServer();
        this.m_PendingExchangeContext.cipherServerToClient = packet.pickCipherServerToClient();
        this.m_PendingExchangeContext.macAlgorithmClientToServer = packet.pickMACAlgorithmClientToServer();
        this.m_PendingExchangeContext.macAlgorithmServerToClient = packet.pickMACAlgorithmServerToClient();
        this.m_PendingExchangeContext.compressionClientToServer = packet.pickCompressionAlgorithmClientToServer();
        this.m_PendingExchangeContext.compressionServerToClient = packet.pickCompressionAlgorithmServerToClient();

        SSHLogger.logDebug(util.format("Selected KexAlgorithm: %s", this.m_PendingExchangeContext.kexAlgorithm.getName()));
        SSHLogger.logDebug(util.format("Selected HostKeyAlgorithm: %s", this.m_PendingExchangeContext.hostKeyAlgorithm.getName()));
        SSHLogger.logDebug(util.format("Selected CipherClientToServer: %s", this.m_PendingExchangeContext.cipherClientToServer.getName()));
        SSHLogger.logDebug(util.format("Selected CipherServerToClient: %s", this.m_PendingExchangeContext.cipherServerToClient.getName()));
        SSHLogger.logDebug(util.format("Selected MACAlgorithmClientToServer: %s", this.m_PendingExchangeContext.macAlgorithmClientToServer.getName()));
        SSHLogger.logDebug(util.format("Selected MACAlgorithmServerToClient: %s", this.m_PendingExchangeContext.macAlgorithmServerToClient.getName()));
        SSHLogger.logDebug(util.format("Selected CompressionClientToServer: %s", this.m_PendingExchangeContext.compressionClientToServer.getName()));
        SSHLogger.logDebug(util.format("Selected CompressionServerToClient: %s", this.m_PendingExchangeContext.compressionServerToClient.getName()));
    }

    private handleKexDHInit(packet: Packets.KexDHInit): void {
        SSHLogger.logDebug("Received KexDHInit");

        if ((this.m_PendingExchangeContext === null) || (this.m_PendingExchangeContext.kexAlgorithm === null)) {
            throw new Exceptions.SSHServerException(
                Exceptions.DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                "Server did not receive SSH_MSG_KEX_INIT as expected.");
        }

        // 1. C generates a random number x (1 < x < q) and computes e = g ^ x mod p.  C sends e to S.
        // 2. S receives e.  It computes K = e^y mod p
        let sharedSecret: Buffer = this.m_PendingExchangeContext.kexAlgorithm.decryptKeyExchange(packet.clientValue);

        // 2. S generates a random number y (0 < y < q) and computes f = g ^ y mod p.
        let serverKeyExchange: Buffer = this.m_PendingExchangeContext.kexAlgorithm.createKeyExchange();

        let hostKey: Buffer = this.m_PendingExchangeContext.hostKeyAlgorithm.createKeyAndCertificatesData();

        // h = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
        let exchangeHash: Buffer = this.computeExchangeHash(
            this.m_PendingExchangeContext.kexAlgorithm,
            hostKey,
            packet.clientValue,
            serverKeyExchange,
            sharedSecret);

        if (this.m_SessionId === null) {
            this.m_SessionId = exchangeHash;
        }

        // initial IV client to server: HASH(K || H || "A" || session_id)
        // (Here K is encoded as mpint and "A" as byte and session_id as raw
        // data.  "A" means the single character A, ASCII 65).
        let clientCipherIV: Buffer = this.computeEncryptionKey(
            this.m_PendingExchangeContext.kexAlgorithm,
            exchangeHash,
            this.m_PendingExchangeContext.cipherClientToServer.getBlockSize(),
            sharedSecret, "A");

        // initial IV server to client: HASH(K || H || "B" || session_id)
        let serverCipherIV: Buffer = this.computeEncryptionKey(
            this.m_PendingExchangeContext.kexAlgorithm,
            exchangeHash,
            this.m_PendingExchangeContext.cipherServerToClient.getBlockSize(),
            sharedSecret, "B");

        // encryption key client to server: HASH(K || H || "C" || session_id)
        let clientCipherKey: Buffer = this.computeEncryptionKey(
            this.m_PendingExchangeContext.kexAlgorithm,
            exchangeHash,
            this.m_PendingExchangeContext.cipherClientToServer.getKeySize(),
            sharedSecret, "C");

        // encryption key server to client: HASH(K || H || "D" || session_id)
        let serverCipherKey: Buffer = this.computeEncryptionKey(
            this.m_PendingExchangeContext.kexAlgorithm,
            exchangeHash,
            this.m_PendingExchangeContext.cipherServerToClient.getKeySize(),
            sharedSecret, "D");

        // integrity key client to server: HASH(K || H || "E" || session_id)
        let clientHmacKey: Buffer = this.computeEncryptionKey(
            this.m_PendingExchangeContext.kexAlgorithm,
            exchangeHash,
            this.m_PendingExchangeContext.macAlgorithmClientToServer.getKeySize(),
            sharedSecret, "E");

        // integrity key server to client: HASH(K || H || "F" || session_id)
        let serverHmacKey: Buffer = this.computeEncryptionKey(
            this.m_PendingExchangeContext.kexAlgorithm,
            exchangeHash,
            this.m_PendingExchangeContext.macAlgorithmServerToClient.getKeySize(),
            sharedSecret, "F");

        // set all keys we just generated
        this.m_PendingExchangeContext.cipherClientToServer.setKey(clientCipherKey, clientCipherIV);
        this.m_PendingExchangeContext.cipherServerToClient.setKey(serverCipherKey, serverCipherIV);
        this.m_PendingExchangeContext.macAlgorithmClientToServer.setKey(clientHmacKey);
        this.m_PendingExchangeContext.macAlgorithmServerToClient.setKey(serverHmacKey);

        let reply: Packets.KexDHReply = new Packets.KexDHReply();
        reply.serverHostKey = hostKey;
        reply.serverValue = serverKeyExchange;
        reply.signature = this.m_PendingExchangeContext.hostKeyAlgorithm.createSignatureData(exchangeHash);

        this.sendPacket(reply);
        this.sendPacket(new Packets.NewKeys());
    }

    private handleNewKeys(packet: Packets.NewKeys): void {
        SSHLogger.logDebug("Received NewKeys");

        this.m_ActiveExchangeContext = this.m_PendingExchangeContext;
        this.m_PendingExchangeContext = null;

        this.m_TotalBytesTransferred = 0;
        this.resetKeyTimer();
    }

    private handleDisconnect(packet: Packets.Disconnect): void {
        this.disconnect(packet.reason, packet.description);
    }

    private sendRaw(data: Buffer): void {
        if (!this.getIsConnected()) {
            return;
        }

        // increase bytes transferred
        this.m_TotalBytesTransferred += data.byteLength;

        this.m_Socket.write(new Buffer(data));
    }

    private closeReceived(hadError: boolean): void {
        this.disconnect(
            Exceptions.DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST,
            "The client disconnected.");
    }

    private getIsDataAvailable(): boolean {
        if (this.m_Socket == null) {
            return false;
        }

        return (this.m_Socket.bytesRead !== this.m_LastBytesRead);
    }

    private readBytes(size: number): Buffer {
        if (this.m_Socket == null) {
            return null;
        }

        let buffer: Buffer = this.m_Socket.read(size);

        if (buffer === null) {
            throw new Exceptions.SSHServerException(
                Exceptions.DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST,
                "Failed to read from socket.");
        }

        if (buffer.byteLength !== size) {
            throw new Exceptions.SSHServerException(
                Exceptions.DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST,
                "Failed to read from socket.");
        }

        this.m_LastBytesRead += size;

        return buffer;
    }

    private getDataAvailable(): number {
        if (this.m_Socket == null) {
            return 0;
        }

        return (this.m_Socket.bytesRead - this.m_LastBytesRead);
    }

    private readProtocolVersionExchange(): void {
        let data: Array<number> = new Array<number>();

        let foundCR: boolean = false;
        let value: Buffer = this.readBytes(1);
        while (value != null) {
            if (foundCR && (value[0] === 10)) {
                // done
                this.m_HasCompletedProtocolVersionExchange = true;
                break;
            }

            if (value[0] === 13) {
                foundCR = true;
            } else {
                foundCR = false;
                data.push(value[0]);
            }

            value = this.readBytes(1);
        }

        this.m_ProtocolVersionExchange += new Buffer(data).toString("UTF8");
    }

    private readPacket(): Packets.Packet {
        if (this.m_Socket == null) {
            return;
        }

        let blockSize: number = this.m_ActiveExchangeContext.cipherClientToServer.getBlockSize();

        // we must have at least 1 block to read
        if (this.getDataAvailable() < blockSize) {
            return null;  // packet not here
        }

        let firstBlock: Buffer = this.m_ActiveExchangeContext.cipherClientToServer.decrypt(this.readBytes(blockSize));

        let reader: ByteReader = new ByteReader(firstBlock);

        // uint32    packet_length
        // packet_length
        //     the length of the packet in bytes, not including 'mac' or the
        //     'packet_length' field itself.
        let packetLength: number = reader.getUInt32();
        if (packetLength > Packets.Packet.MaxPacketSize) {
            throw new Exceptions.SSHServerException(
                Exceptions.DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                util.format(
                    "Client tried to send a packet bigger than MaxPacketSize (%d bytes): %d bytes",
                    Packets.Packet.MaxPacketSize,
                    packetLength));
        }

        // byte      padding_length
        // padding_length
        //    length of 'random padding' (bytes).
        let paddingLength: number = reader.getByte();

        // byte[n1]  payload; n1 = packet_length - padding_length - 1
        // payload
        //    the useful contents of the packet.  If compression has been
        //    negotiated, this field is compressed.  Initially, compression
        //    must be "none".
        let bytesToRead: number = packetLength - blockSize + 4;

        let restOfPacket: Buffer = this.m_ActiveExchangeContext.cipherClientToServer.decrypt(this.readBytes(bytesToRead));

        let payloadLength: number = packetLength - paddingLength - 1;
        let fullPacket: Buffer = Buffer.concat([ firstBlock, restOfPacket ]);

        // track total bytes read
        this.m_TotalBytesTransferred += fullPacket.byteLength;

        let payload: Buffer = fullPacket.slice(
            Packets.Packet.PacketHeaderSize,
            Packets.Packet.PacketHeaderSize + payloadLength);

        // byte[n2]  random padding; n2 = padding_length
        // random padding
        //    arbitrary-length padding, such that the total length of
        //    (packet_length || padding_length || payload || random padding)
        //    is a multiple of the cipher block size or 8, whichever is
        //    larger.  There MUST be at least four bytes of padding.  The
        //    padding SHOULD consist of random bytes.  The maximum amount of
        //    padding is 255 bytes.

        // byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        // mac
        //    message Authentication Code.  If message authentication has
        //    been negotiated, this field contains the MAC bytes.  Initially,
        //    the MAC algorithm MUST be "none".

        let packetNumber: number = this.m_CurrentReceivedPacketNumber;
        this.m_CurrentReceivedPacketNumber += 1;

        if (this.m_ActiveExchangeContext.macAlgorithmClientToServer != null) {

            let clientMac: Buffer = this.readBytes(this.m_ActiveExchangeContext.macAlgorithmClientToServer.getDigestLength());
            let mac: Buffer = this.m_ActiveExchangeContext.macAlgorithmClientToServer.computeHash(packetNumber, fullPacket);
            if (clientMac.compare(mac) !== 0) {
                throw new Exceptions.SSHServerException(
                    Exceptions.DisconnectReason.SSH_DISCONNECT_MAC_ERROR,
                    "MAC from client is invalid");
            }
        }

        payload = this.m_ActiveExchangeContext.compressionClientToServer.decompress(payload);

        let packetReader: ByteReader = new ByteReader(payload);
        let packetType: Packets.PacketType = packetReader.getByte();

        let packet: Packets.Packet = Client.createPacket(packetType);

        if (packet != null) {
            SSHLogger.logDebug(util.format("Received Packet: %s", Packets.PacketType[packetType]));
            packet.load(packetReader);
        }

        return packet;
    }

    private considerReExchange(): void {
        const OneGB: number = (1024 * 1024 * 1024);
        if (this.m_TotalBytesTransferred > OneGB) {
            this.reExchangeKeys();
        }
    }

    private resetKeyTimer(): void {
        const MSInOneHour: number = 1000 * 60 * 60;

        if (this.m_KeyTimeout !== null) {
            clearTimeout(this.m_KeyTimeout);
        }

        this.m_KeyTimeout = setTimeout(this.reExchangeKeys, MSInOneHour);
    }

    private reExchangeKeys(): void {
        // time to get new keys!
        this.m_TotalBytesTransferred = 0;
        this.resetKeyTimer();

        SSHLogger.logDebug("Trigger re-exchange from server");
        this.m_PendingExchangeContext = new ExchangeContext();
        this.sendPacket(this.m_KexInitServerToClient);
    }

    private computeExchangeHash(
        kexAlgorithm: IKexAlgorithm,
        hostKeyAndCerts: Buffer,
        clientExchangeValue: Buffer,
        serverExchangeValue: Buffer,
        sharedSecret: Buffer): Buffer {
        let writer: ByteWriter = new ByteWriter();
        writer.writeString(this.m_ProtocolVersionExchange);
        writer.writeString(Server.ProtocolVersionExchange);

        writer.writeBytes(this.m_KexInitClientToServer.getBytes());
        writer.writeBytes(this.m_KexInitServerToClient.getBytes());
        writer.writeBytes(hostKeyAndCerts);

        writer.writeMPInt(clientExchangeValue);
        writer.writeMPInt(serverExchangeValue);
        writer.writeMPInt(sharedSecret);

        return kexAlgorithm.computeHash(writer.toBuffer());
    }

    private computeEncryptionKey(kexAlgorithm: IKexAlgorithm, exchangeHash: Buffer, keySize: number, sharedSecret: Buffer, letter: string): Buffer {
        // k(X) = HASH(K || H || X || session_id)

        // prepare the buffer
        let keyBuffer: Buffer = new Buffer(keySize);
        let keyBufferIndex: number = 0;
        let currentHashLength: number = 0;
        let currentHash: Buffer = null;

        // we can stop once we fill the key buffer
        while (keyBufferIndex < keySize) {
            let writer: ByteWriter = new ByteWriter();
            // write "K"
            writer.writeMPInt(sharedSecret);

            // write "H"
            writer.writeRawBytes(exchangeHash);

            if (currentHash === null) {
                // if we haven't done this yet, add the "X" and session_id
                writer.writeByte(letter.charCodeAt(0));
                writer.writeRawBytes(this.m_SessionId);
            } else {
                // if the key isn't long enough after the first pass, we need to
                // write the current hash as described here:
                //      k1 = HASH(K || H || X || session_id)   (X is e.g., "A")
                //      k2 = HASH(K || H || K1)
                //      k3 = HASH(K || H || K1 || K2)
                //      ...
                //      key = K1 || K2 || K3 || ...
                writer.writeRawBytes(currentHash);
            }

            currentHash = kexAlgorithm.computeHash(writer.toBuffer());

            currentHashLength = Math.min(currentHash.byteLength, (keySize - keyBufferIndex));
            currentHash.copy(keyBuffer, keyBufferIndex, 0, currentHashLength);

            keyBufferIndex += currentHashLength;
        }

        return keyBuffer;
    }

    private validateProtocolVersionExchange(): void {
        // https://tools.ietf.org/html/rfc4253#section-4.2
        // -   SSH-protoversion-softwareversion SP comments
        let pveParts: string[] = this.m_ProtocolVersionExchange.split(" ");
        if (pveParts.length == 0) {
            throw new Error("Invalid Protocol Version Exchange was received - No Data");
        }

        let versionParts: string[] = pveParts[0].split("-");
        if (versionParts.length < 3) {
            throw new Error(util.format("Invalid Protocol Version Exchange was received - Not enough dashes - %s", pveParts[0]));
        }

        if (versionParts[1] !== "2.0") {
            throw new Error(util.format("Invalid Protocol Version Exchange was received - Unsupported Version - %s", versionParts[1]));
        }

        // if we get here, all is well!
    }

    private static createPacket(packetType: Packets.PacketType): Packets.Packet {
        switch (packetType) {
            case Packets.PacketType.SSH_MSG_KEXINIT:
                return new Packets.KexInit();
            case Packets.PacketType.SSH_MSG_KEXDH_INIT:
                return new Packets.KexDHInit();
            case Packets.PacketType.SSH_MSG_NEWKEYS:
                return new Packets.NewKeys();
            case Packets.PacketType.SSH_MSG_DISCONNECT:
                return new Packets.Disconnect();
        }

        SSHLogger.logDebug(util.format("Unknown PacketType: %s", Packets.PacketType[packetType]));
        return null;
    }
}
