using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Extensions.Logging;
using SSHServer.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

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
                    Disconnect();
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
                            // TODO: Consider processing Protocol Version Exchange for validity
                            m_Logger.LogDebug($"Received ProtocolVersionExchange: {m_ProtocolVersionExchange}");
                        }
                    }
                    catch (Exception)
                    {
                        Disconnect();
                        return;
                    }
                }

                if (m_HasCompletedProtocolVersionExchange)
                {
                    try
                    {
                        Packet packet = Packet.ReadPacket(m_Socket);
                        while (packet != null)
                        {
                            m_Logger.LogDebug($"Received Packet: {packet.PacketType}");
                            HandlePacket(packet);
                            packet = Packet.ReadPacket(m_Socket);
                        }
                    }
                    catch (Exception ex)
                    {
                        m_Logger.LogError(ex.Message);
                        Disconnect();
                        return;
                    }
                }
            }
        }

        public void Disconnect()
        {
            m_Logger.LogDebug($"Disconnected");
            if (m_Socket != null)
            {
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
            catch(RuntimeBinderException)
            {
                // TODO: Send an SSH_MSG_UNIMPLEMENTED if we get here
            }
        }

        private void HandleSpecificPacket(KexInit packet)
        {
            m_Logger.LogDebug("Received KexInit");

            if (m_PendingExchangeContext == null)
            {
                m_Logger.LogDebug("Re-exchanging keys!");
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

        private void Send(string message)
        {
            m_Logger.LogDebug($"Sending raw string: {message.Trim()}");
            Send(Encoding.UTF8.GetBytes(message));
        }

        private void Send(byte[] data)
        {
            if (!IsConnected)
                return;

            m_Socket.Send(data);
        }

        public void Send(Packet packet)
        {
            Send(packet.ToByteArray());
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
    }
}
