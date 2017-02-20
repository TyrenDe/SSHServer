using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Extensions.Logging;
using SSHServer.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using SSHServer.KexAlgorithms;
using System.Threading;
using System.Security.Cryptography;

namespace SSHServer
{
    public class Client
    {
        private Socket m_Socket;
        private ILogger m_Logger;

        private bool m_HasCompletedProtocolVersionExchange = false;
        private string m_ProtocolVersionExchange;

        private KexInit m_KexInitServerToClient = new KexInit();
        private KexInit m_KexInitClientToServer = null;
        private byte[] m_SessionId = null;

        private int m_CurrentSentPacketNumber = -1;
        private int m_CurrentReceivedPacketNumber = -1;

        private long m_TotalBytesTransferred = 0;
        private DateTime m_KeyTimeout = DateTime.UtcNow.AddHours(1);

        private ExchangeContext m_ActiveExchangeContext = new ExchangeContext();
        private ExchangeContext m_PendingExchangeContext = new ExchangeContext();

        // We are considered connected if we have a valid socket object
        public bool IsConnected { get { return m_Socket != null; } }

        public Client(Socket socket, ILogger logger)
        {
            m_Socket = socket;
            m_Logger = logger;

            m_KexInitServerToClient.KexAlgorithms.AddRange(Server.GetNames(Server.SupportedKexAlgorithms));
            m_KexInitServerToClient.ServerHostKeyAlgorithms.AddRange(Server.GetNames(Server.SupportedHostKeyAlgorithms));
            m_KexInitServerToClient.EncryptionAlgorithmsClientToServer.AddRange(Server.GetNames(Server.SupportedCiphers));
            m_KexInitServerToClient.EncryptionAlgorithmsServerToClient.AddRange(Server.GetNames(Server.SupportedCiphers));
            m_KexInitServerToClient.MacAlgorithmsClientToServer.AddRange(Server.GetNames(Server.SupportedMACAlgorithms));
            m_KexInitServerToClient.MacAlgorithmsServerToClient.AddRange(Server.GetNames(Server.SupportedMACAlgorithms));
            m_KexInitServerToClient.CompressionAlgorithmsClientToServer.AddRange(Server.GetNames(Server.SupportedCompressions));
            m_KexInitServerToClient.CompressionAlgorithmsServerToClient.AddRange(Server.GetNames(Server.SupportedCompressions));

            const int socketBufferSize = 2 * Packet.MaxPacketSize;
            m_Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, socketBufferSize);
            m_Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, socketBufferSize);
            m_Socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            m_Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.DontLinger, true);

            // 4.2.Protocol Version Exchange - https://tools.ietf.org/html/rfc4253#section-4.2
            Send($"{Server.ProtocolVersionExchange}\r\n");

            // 7.1.  Algorithm Negotiation - https://tools.ietf.org/html/rfc4253#section-7.1
            Send(m_KexInitServerToClient);
        }

        public void Poll()
        {
            if (!IsConnected)
                return;

            bool dataAvailable = m_Socket.Poll(0, SelectMode.SelectRead);
            if (dataAvailable)
            {
                int read = m_Socket.Available;
                if (read < 1)
                {
                    Disconnect(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "The client disconnected.");
                    return;
                }

                if (!m_HasCompletedProtocolVersionExchange)
                {
                    // Wait for CRLF
                    try
                    {
                        ReadProtocolVersionExchange();
                        if (m_HasCompletedProtocolVersionExchange)
                        {
                            m_Logger.LogDebug($"Received ProtocolVersionExchange: {m_ProtocolVersionExchange}");
                            ValidateProtocolVersionExchange();
                        }
                    }
                    catch (Exception ex)
                    {
                        m_Logger.LogError(ex.Message);
                        Disconnect(DisconnectReason.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, "Failed to get the protocol version exchange.");
                        return;
                    }
                }

                if (m_HasCompletedProtocolVersionExchange)
                {
                    try
                    {
                        Packet packet = ReadPacket();
                        while (packet != null)
                        {
                            m_Logger.LogDebug($"Received Packet: {packet.PacketType}");
                            HandlePacket(packet);
                            packet = ReadPacket();
                        }

                        ConsiderReExchange();
                    }
                    catch (SSHServerException ex)
                    {
                        m_Logger.LogError(ex.Message);
                        Disconnect(ex.Reason, ex.Message);
                        return;
                    }
                    catch (Exception ex)
                    {
                        m_Logger.LogError(ex.Message);
                        Disconnect(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, ex.Message);
                        return;
                    }
                }
            }
        }

        public void Disconnect(DisconnectReason reason, string message)
        {
            m_Logger.LogDebug($"Disconnected - {reason} - {message}");
            if (m_Socket != null)
            {
                if (reason != DisconnectReason.None)
                {
                    try
                    {
                        Disconnect disconnect = new Disconnect()
                        {
                            Reason = reason,
                            Description = message
                        };
                        Send(disconnect);
                    }
                    catch (Exception) { }
                }

                try
                {
                    m_Socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception) { }

                m_Socket = null;
            }
        }

        private void HandlePacket(Packet packet)
        {
            try
            {
                HandleSpecificPacket((dynamic)packet);
            }
            catch (RuntimeBinderException)
            {
                m_Logger.LogWarning($"Unhandled packet type: {packet.PacketType}");

                Unimplemented unimplemented = new Unimplemented()
                {
                    RejectedPacketNumber = packet.PacketSequence
                };
                Send(unimplemented);
            }
        }

        private void HandleSpecificPacket(KexInit packet)
        {
            m_Logger.LogDebug("Received KexInit");

            if (m_PendingExchangeContext == null)
            {
                m_Logger.LogDebug("Trigger re-exchange from client");
                m_PendingExchangeContext = new ExchangeContext();
                Send(m_KexInitServerToClient);
            }

            m_KexInitClientToServer = packet;

            m_PendingExchangeContext.KexAlgorithm = packet.PickKexAlgorithm();
            m_PendingExchangeContext.HostKeyAlgorithm = packet.PickHostKeyAlgorithm();
            m_PendingExchangeContext.CipherClientToServer = packet.PickCipherClientToServer();
            m_PendingExchangeContext.CipherServerToClient = packet.PickCipherServerToClient();
            m_PendingExchangeContext.MACAlgorithmClientToServer = packet.PickMACAlgorithmClientToServer();
            m_PendingExchangeContext.MACAlgorithmServerToClient = packet.PickMACAlgorithmServerToClient();
            m_PendingExchangeContext.CompressionClientToServer = packet.PickCompressionAlgorithmClientToServer();
            m_PendingExchangeContext.CompressionServerToClient = packet.PickCompressionAlgorithmServerToClient();

            m_Logger.LogDebug($"Selected KexAlgorithm: {m_PendingExchangeContext.KexAlgorithm.Name}");
            m_Logger.LogDebug($"Selected HostKeyAlgorithm: {m_PendingExchangeContext.HostKeyAlgorithm.Name}");
            m_Logger.LogDebug($"Selected CipherClientToServer: {m_PendingExchangeContext.CipherClientToServer.Name}");
            m_Logger.LogDebug($"Selected CipherServerToClient: {m_PendingExchangeContext.CipherServerToClient.Name}");
            m_Logger.LogDebug($"Selected MACAlgorithmClientToServer: {m_PendingExchangeContext.MACAlgorithmClientToServer.Name}");
            m_Logger.LogDebug($"Selected MACAlgorithmServerToClient: {m_PendingExchangeContext.MACAlgorithmServerToClient.Name}");
            m_Logger.LogDebug($"Selected CompressionClientToServer: {m_PendingExchangeContext.CompressionClientToServer.Name}");
            m_Logger.LogDebug($"Selected CompressionServerToClient: {m_PendingExchangeContext.CompressionServerToClient.Name}");
        }

        private void HandleSpecificPacket(KexDHInit packet)
        {
            m_Logger.LogDebug("Received KexDHInit");

            if ((m_PendingExchangeContext == null) || (m_PendingExchangeContext.KexAlgorithm == null))
            {
                throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, "Server did not receive SSH_MSG_KEX_INIT as expected.");
            }

            // 1. C generates a random number x (1 < x < q) and computes e = g ^ x mod p.  C sends e to S.
            // 2. S receives e.  It computes K = e^y mod p
            byte[] sharedSecret = m_PendingExchangeContext.KexAlgorithm.DecryptKeyExchange(packet.ClientValue);

            // 2. S generates a random number y (0 < y < q) and computes f = g ^ y mod p.
            byte[] serverKeyExchange = m_PendingExchangeContext.KexAlgorithm.CreateKeyExchange();

            byte[] hostKey = m_PendingExchangeContext.HostKeyAlgorithm.CreateKeyAndCertificatesData();

            // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
            byte[] exchangeHash = ComputeExchangeHash(
                m_PendingExchangeContext.KexAlgorithm,
                hostKey,
                packet.ClientValue,
                serverKeyExchange,
                sharedSecret);

            if (m_SessionId == null)
                m_SessionId = exchangeHash;

            // https://tools.ietf.org/html/rfc4253#section-7.2

            // Initial IV client to server: HASH(K || H || "A" || session_id)
            // (Here K is encoded as mpint and "A" as byte and session_id as raw
            // data.  "A" means the single character A, ASCII 65).
            byte[] clientCipherIV = ComputeEncryptionKey(
                m_PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                m_PendingExchangeContext.CipherClientToServer.BlockSize,
                sharedSecret, 'A');

            // Initial IV server to client: HASH(K || H || "B" || session_id)
            byte[] serverCipherIV = ComputeEncryptionKey(
                m_PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                m_PendingExchangeContext.CipherServerToClient.BlockSize,
                sharedSecret, 'B');

            // Encryption key client to server: HASH(K || H || "C" || session_id)
            byte[] clientCipherKey = ComputeEncryptionKey(
                m_PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                m_PendingExchangeContext.CipherClientToServer.KeySize,
                sharedSecret, 'C');

            // Encryption key server to client: HASH(K || H || "D" || session_id)
            byte[] serverCipherKey = ComputeEncryptionKey(
                m_PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                m_PendingExchangeContext.CipherServerToClient.KeySize,
                sharedSecret, 'D');

            // Integrity key client to server: HASH(K || H || "E" || session_id)
            byte[] clientHmacKey = ComputeEncryptionKey(
                m_PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                m_PendingExchangeContext.MACAlgorithmClientToServer.KeySize,
                sharedSecret, 'E');

            // Integrity key server to client: HASH(K || H || "F" || session_id)
            byte[] serverHmacKey = ComputeEncryptionKey(
                m_PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                m_PendingExchangeContext.MACAlgorithmServerToClient.KeySize,
                sharedSecret, 'F');

            // Set all keys we just generated
            m_PendingExchangeContext.CipherClientToServer.SetKey(clientCipherKey, clientCipherIV);
            m_PendingExchangeContext.CipherServerToClient.SetKey(serverCipherKey, serverCipherIV);
            m_PendingExchangeContext.MACAlgorithmClientToServer.SetKey(clientHmacKey);
            m_PendingExchangeContext.MACAlgorithmServerToClient.SetKey(serverHmacKey);

            // Send reply to client!
            KexDHReply reply = new KexDHReply()
            {
                ServerHostKey = hostKey,
                ServerValue = serverKeyExchange,
                Signature = m_PendingExchangeContext.HostKeyAlgorithm.CreateSignatureData(exchangeHash)
            };

            Send(reply);
            Send(new NewKeys());
        }

        private void HandleSpecificPacket(NewKeys packet)
        {
            m_Logger.LogDebug("Received NewKeys");

            m_ActiveExchangeContext = m_PendingExchangeContext;
            m_PendingExchangeContext = null;

            // Reset re-exchange values
            m_TotalBytesTransferred = 0;
            m_KeyTimeout = DateTime.UtcNow.AddHours(1);
        }

        private void HandleSpecificPacket(Disconnect packet)
        {
            this.Disconnect(packet.Reason, packet.Description);
        }

        private byte[] ComputeExchangeHash(IKexAlgorithm kexAlgorithm, byte[] hostKeyAndCerts, byte[] clientExchangeValue, byte[] serverExchangeValue, byte[] sharedSecret)
        {
            // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteString(m_ProtocolVersionExchange);
                writer.WriteString(Server.ProtocolVersionExchange);

                writer.WriteBytes(m_KexInitClientToServer.GetBytes());
                writer.WriteBytes(m_KexInitServerToClient.GetBytes());
                writer.WriteBytes(hostKeyAndCerts);

                writer.WriteMPInt(clientExchangeValue);
                writer.WriteMPInt(serverExchangeValue);
                writer.WriteMPInt(sharedSecret);

                return kexAlgorithm.ComputeHash(writer.ToByteArray());
            }
        }

        private byte[] ComputeEncryptionKey(IKexAlgorithm kexAlgorithm, byte[] exchangeHash, uint keySize, byte[] sharedSecret, char letter)
        {
            // K(X) = HASH(K || H || X || session_id)

            // Prepare the buffer
            byte[] keyBuffer = new byte[keySize];
            int keyBufferIndex = 0;
            int currentHashLength = 0;
            byte[] currentHash = null;

            // We can stop once we fill the key buffer
            while (keyBufferIndex < keySize)
            {
                using (ByteWriter writer = new ByteWriter())
                {
                    // Write "K"
                    writer.WriteMPInt(sharedSecret);

                    // Write "H"
                    writer.WriteRawBytes(exchangeHash);

                    if (currentHash == null)
                    {
                        // If we haven't done this yet, add the "X" and session_id
                        writer.WriteByte((byte)letter);
                        writer.WriteRawBytes(m_SessionId);
                    }
                    else
                    {
                        // If the key isn't long enough after the first pass, we need to
                        // write the current hash as described here:
                        //      K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
                        //      K2 = HASH(K || H || K1)
                        //      K3 = HASH(K || H || K1 || K2)
                        //      ...
                        //      key = K1 || K2 || K3 || ...
                        writer.WriteRawBytes(currentHash);
                    }

                    currentHash = kexAlgorithm.ComputeHash(writer.ToByteArray());
                }

                currentHashLength = Math.Min(currentHash.Length, (int)(keySize - keyBufferIndex));
                Array.Copy(currentHash, 0, keyBuffer, keyBufferIndex, currentHashLength);

                keyBufferIndex += currentHashLength;
            }

            return keyBuffer;
        }

        private void Send(string message)
        {
            m_Logger.LogDebug($"Sending raw string: {message.Trim()}");
            Send(Encoding.UTF8.GetBytes(message));
        }

        private void Send(byte[] data)
        {
            if (!IsConnected)
                return;

            // Increase bytes transferred
            m_TotalBytesTransferred += data.Length;

            m_Socket.Send(data);
        }

        public void Send(Packet packet)
        {
            packet.PacketSequence = GetSentPacketNumber();

            byte[] payload = m_ActiveExchangeContext.CompressionServerToClient.Compress(packet.GetBytes());

            uint blockSize = m_ActiveExchangeContext.CipherServerToClient.BlockSize;

            byte paddingLength = (byte)(blockSize - (payload.Length + 5) % blockSize);
            if (paddingLength < 4)
                paddingLength += (byte)blockSize;

            byte[] padding = new byte[paddingLength];
            RandomNumberGenerator.Create().GetBytes(padding);

            uint packetLength = (uint)(payload.Length + paddingLength + 1);

            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteUInt32(packetLength);
                writer.WriteByte(paddingLength);
                writer.WriteRawBytes(payload);
                writer.WriteRawBytes(padding);

                payload = writer.ToByteArray();
            }

            byte[] encryptedPayload = m_ActiveExchangeContext.CipherServerToClient.Encrypt(payload);
            if (m_ActiveExchangeContext.MACAlgorithmServerToClient != null)
            {
                byte[] mac = m_ActiveExchangeContext.MACAlgorithmServerToClient.ComputeHash(packet.PacketSequence, payload);
                encryptedPayload = encryptedPayload.Concat(mac).ToArray();
            }

            Send(encryptedPayload);
            this.ConsiderReExchange();
        }

        private uint GetSentPacketNumber()
        {
            return (uint)Interlocked.Increment(ref m_CurrentSentPacketNumber);
        }

        private uint GetReceivedPacketNumber()
        {
            return (uint)Interlocked.Increment(ref m_CurrentReceivedPacketNumber);
        }

        // Read 1 byte from the socket until we find "\r\n"
        private void ReadProtocolVersionExchange()
        {
            NetworkStream stream = new NetworkStream(m_Socket, false);
            string result = null;

            List<byte> data = new List<byte>();

            bool foundCR = false;
            int value = stream.ReadByte();
            while (value != -1)
            {
                if (foundCR && (value == '\n'))
                {
                    // DONE
                    result = Encoding.UTF8.GetString(data.ToArray());
                    m_HasCompletedProtocolVersionExchange = true;
                    break;
                }

                if (value == '\r')
                    foundCR = true;
                else
                {
                    foundCR = false;
                    data.Add((byte)value);
                }

                value = stream.ReadByte();
            }

            m_ProtocolVersionExchange += result;
        }

        public Packet ReadPacket()
        {
            if (m_Socket == null)
                return null;

            uint blockSize = m_ActiveExchangeContext.CipherClientToServer.BlockSize;

            // We must have at least 1 block to read
            if (m_Socket.Available < blockSize)
                return null;  // Packet not here

            byte[] firstBlock = new byte[blockSize];
            int bytesRead = m_Socket.Receive(firstBlock);
            if (bytesRead != blockSize)
                throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "Failed to read from socket.");

            firstBlock = m_ActiveExchangeContext.CipherClientToServer.Decrypt(firstBlock);

            uint packetLength = 0;
            byte paddingLength = 0;
            using (ByteReader reader = new ByteReader(firstBlock))
            {
                // uint32    packet_length
                // packet_length
                //     The length of the packet in bytes, not including 'mac' or the
                //     'packet_length' field itself.
                packetLength = reader.GetUInt32();
                if (packetLength > Packet.MaxPacketSize)
                    throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, $"Client tried to send a packet bigger than MaxPacketSize ({Packet.MaxPacketSize} bytes): {packetLength} bytes");

                // byte      padding_length
                // padding_length
                //    Length of 'random padding' (bytes).
                paddingLength = reader.GetByte();
            }

            // byte[n1]  payload; n1 = packet_length - padding_length - 1
            // payload
            //    The useful contents of the packet.  If compression has been
            //    negotiated, this field is compressed.  Initially, compression
            //    MUST be "none".
            uint bytesToRead = packetLength - blockSize + 4;

            byte[] restOfPacket = new byte[bytesToRead];
            bytesRead = m_Socket.Receive(restOfPacket);
            if (bytesRead != bytesToRead)
                throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "Failed to read from socket.");

            restOfPacket = m_ActiveExchangeContext.CipherClientToServer.Decrypt(restOfPacket);

            uint payloadLength = packetLength - paddingLength - 1;
            byte[] fullPacket = firstBlock.Concat(restOfPacket).ToArray();

            // Track total bytes read
            m_TotalBytesTransferred += fullPacket.Length;

            byte[] payload = fullPacket.Skip(Packet.PacketHeaderSize).Take((int)(packetLength - paddingLength - 1)).ToArray();

            // byte[n2]  random padding; n2 = padding_length
            // random padding
            //    Arbitrary-length padding, such that the total length of
            //    (packet_length || padding_length || payload || random padding)
            //    is a multiple of the cipher block size or 8, whichever is
            //    larger.  There MUST be at least four bytes of padding.  The
            //    padding SHOULD consist of random bytes.  The maximum amount of
            //    padding is 255 bytes.

            // byte[m]   mac (Message Authentication Code - MAC); m = mac_length
            // mac
            //    Message Authentication Code.  If message authentication has
            //    been negotiated, this field contains the MAC bytes.  Initially,
            //    the MAC algorithm MUST be "none".

            uint packetNumber = GetReceivedPacketNumber();
            if (m_ActiveExchangeContext.MACAlgorithmClientToServer != null)
            {
                byte[] clientMac = new byte[m_ActiveExchangeContext.MACAlgorithmClientToServer.DigestLength];
                bytesRead = m_Socket.Receive(clientMac);
                if (bytesRead != m_ActiveExchangeContext.MACAlgorithmClientToServer.DigestLength)
                    throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "Failed to read from socket.");

                var mac = m_ActiveExchangeContext.MACAlgorithmClientToServer.ComputeHash(packetNumber, fullPacket);
                if (!clientMac.SequenceEqual(mac))
                {
                    throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_MAC_ERROR, "MAC from client is invalid");
                }
            }

            payload = m_ActiveExchangeContext.CompressionClientToServer.Decompress(payload);

            using (ByteReader packetReader = new ByteReader(payload))
            {
                PacketType type = (PacketType)packetReader.GetByte();

                if (Packet.PacketTypes.ContainsKey(type))
                {

                    Packet packet = Activator.CreateInstance(Packet.PacketTypes[type]) as Packet;
                    packet.Load(packetReader);
                    packet.PacketSequence = packetNumber;
                    return packet;
                }

                m_Logger.LogWarning($"Unimplemented packet type: {type}");

                Unimplemented unimplemented = new Unimplemented()
                {
                    RejectedPacketNumber = packetNumber
                };
                Send(unimplemented);
            }

            return null;
        }

        private void ConsiderReExchange()
        {
            const long OneGB = (1024 * 1024 * 1024);
            if ((m_TotalBytesTransferred > OneGB) || (m_KeyTimeout < DateTime.UtcNow))
            {
                // Time to get new keys!
                m_TotalBytesTransferred = 0;
                m_KeyTimeout = DateTime.UtcNow.AddHours(1);

                m_Logger.LogDebug("Trigger re-exchange from server");
                m_PendingExchangeContext = new ExchangeContext();
                Send(m_KexInitServerToClient);
            }
        }

        private void ValidateProtocolVersionExchange()
        {
            // https://tools.ietf.org/html/rfc4253#section-4.2
            //SSH-protoversion-softwareversion SP comments

            string[] pveParts = m_ProtocolVersionExchange.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (pveParts.Length == 0)
                throw new UnauthorizedAccessException("Invalid Protocol Version Exchange was received - No Data");

            string[] versionParts = pveParts[0].Split(new char[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (versionParts.Length < 3)
                throw new UnauthorizedAccessException($"Invalid Protocol Version Exchange was received - Not enough dashes - {pveParts[0]}");

            if (versionParts[1] != "2.0")
                throw new UnauthorizedAccessException($"Invalid Protocol Version Exchange was received - Unsupported Version - {versionParts[1]}");

            // If we get here, all is well!
        }
    }
}
