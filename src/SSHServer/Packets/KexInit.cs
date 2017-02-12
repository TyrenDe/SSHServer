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

        protected override void Load(ByteReader reader)
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
    }
}
