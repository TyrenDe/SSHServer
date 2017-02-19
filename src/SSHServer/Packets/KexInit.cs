using SSHServer.Ciphers;
using SSHServer.Compressions;
using SSHServer.HostKeyAlgorithms;
using SSHServer.KexAlgorithms;
using SSHServer.MACAlgorithms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SSHServer.Packets
{
    public class KexInit : Packet
    {
        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_KEXINIT;
            }
        }

        public byte[] Cookie { get; set; } = new byte[16];
        public List<string> KexAlgorithms { get; private set; } = new List<string>();
        public List<string> ServerHostKeyAlgorithms { get; private set; } = new List<string>();
        public List<string> EncryptionAlgorithmsClientToServer { get; private set; } = new List<string>();
        public List<string> EncryptionAlgorithmsServerToClient { get; private set; } = new List<string>();
        public List<string> MacAlgorithmsClientToServer { get; private set; } = new List<string>();
        public List<string> MacAlgorithmsServerToClient { get; private set; } = new List<string>();
        public List<string> CompressionAlgorithmsClientToServer { get; private set; } = new List<string>();
        public List<string> CompressionAlgorithmsServerToClient { get; private set; } = new List<string>();
        public List<string> LanguagesClientToServer { get; private set; } = new List<string>();
        public List<string> LanguagesServerToClient { get; private set; } = new List<string>();
        public bool FirstKexPacketFollows { get; set; }

        public KexInit()
        {
            RandomNumberGenerator.Create().GetBytes(Cookie);
        }

        protected override void InternalGetBytes(ByteWriter writer)
        {
            writer.WriteRawBytes(Cookie);
            writer.WriteStringList(KexAlgorithms);
            writer.WriteStringList(ServerHostKeyAlgorithms);
            writer.WriteStringList(EncryptionAlgorithmsClientToServer);
            writer.WriteStringList(EncryptionAlgorithmsServerToClient);
            writer.WriteStringList(MacAlgorithmsClientToServer);
            writer.WriteStringList(MacAlgorithmsServerToClient);
            writer.WriteStringList(CompressionAlgorithmsClientToServer);
            writer.WriteStringList(CompressionAlgorithmsServerToClient);
            writer.WriteStringList(LanguagesClientToServer);
            writer.WriteStringList(LanguagesServerToClient);
            writer.WriteByte(FirstKexPacketFollows ? (byte)0x01 : (byte)0x00);
            writer.WriteUInt32(0);
        }

        public override void Load(ByteReader reader)
        {
            Cookie = reader.GetBytes(16);
            KexAlgorithms = reader.GetNameList();
            ServerHostKeyAlgorithms = reader.GetNameList();
            EncryptionAlgorithmsClientToServer = reader.GetNameList();
            EncryptionAlgorithmsServerToClient = reader.GetNameList();
            MacAlgorithmsClientToServer = reader.GetNameList();
            MacAlgorithmsServerToClient = reader.GetNameList();
            CompressionAlgorithmsClientToServer = reader.GetNameList();
            CompressionAlgorithmsServerToClient = reader.GetNameList();
            LanguagesClientToServer = reader.GetNameList();
            LanguagesServerToClient = reader.GetNameList();
            FirstKexPacketFollows = reader.GetBoolean();
            /*
              uint32       0 (reserved for future extension)
            */
            uint reserved = reader.GetUInt32();
        }

        public IKexAlgorithm PickKexAlgorithm()
        {
            foreach (string algo in this.KexAlgorithms)
            {
                IKexAlgorithm selectedAlgo = Server.GetType<IKexAlgorithm>(Server.SupportedKexAlgorithms, algo);
                if (selectedAlgo != null)
                {
                    return selectedAlgo;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Kex Algorithm");
        }

        public IHostKeyAlgorithm PickHostKeyAlgorithm()
        {
            foreach (string algo in this.ServerHostKeyAlgorithms)
            {
                IHostKeyAlgorithm selectedAlgo = Server.GetType<IHostKeyAlgorithm>(Server.SupportedHostKeyAlgorithms, algo);
                if (selectedAlgo != null)
                {
                    return selectedAlgo;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Host Key Algorithm");
        }

        public ICipher PickCipherClientToServer()
        {
            foreach (string algo in this.EncryptionAlgorithmsClientToServer)
            {
                ICipher selectedCipher = Server.GetType<ICipher>(Server.SupportedCiphers, algo);
                if (selectedCipher != null)
                {
                    return selectedCipher;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Client-To-Server Cipher Algorithm");
        }

        public ICipher PickCipherServerToClient()
        {
            foreach (string algo in this.EncryptionAlgorithmsServerToClient)
            {
                ICipher selectedCipher = Server.GetType<ICipher>(Server.SupportedCiphers, algo);
                if (selectedCipher != null)
                {
                    return selectedCipher;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Server-To-Client Cipher Algorithm");
        }

        public IMACAlgorithm PickMACAlgorithmClientToServer()
        {
            foreach (string algo in this.MacAlgorithmsClientToServer)
            {
                IMACAlgorithm selectedAlgo = Server.GetType<IMACAlgorithm>(Server.SupportedMACAlgorithms, algo);
                if (selectedAlgo != null)
                {
                    return selectedAlgo;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Client-To-Server MAC Algorithm");
        }

        public IMACAlgorithm PickMACAlgorithmServerToClient()
        {
            foreach (string algo in this.MacAlgorithmsServerToClient)
            {
                IMACAlgorithm selectedAlgo = Server.GetType<IMACAlgorithm>(Server.SupportedMACAlgorithms, algo);
                if (selectedAlgo != null)
                {
                    return selectedAlgo;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Server-To-Client MAC Algorithm");
        }

        public ICompression PickCompressionAlgorithmClientToServer()
        {
            foreach (string algo in this.CompressionAlgorithmsClientToServer)
            {
                ICompression selectedAlgo = Server.GetType<ICompression>(Server.SupportedCompressions, algo);
                if (selectedAlgo != null)
                {
                    return selectedAlgo;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Client-To-Server Compression Algorithm");
        }

        public ICompression PickCompressionAlgorithmServerToClient()
        {
            foreach (string algo in this.CompressionAlgorithmsServerToClient)
            {
                ICompression selectedAlgo = Server.GetType<ICompression>(Server.SupportedCompressions, algo);
                if (selectedAlgo != null)
                {
                    return selectedAlgo;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not find a shared Server-To-Client Compresion Algorithm");
        }
    }
}
