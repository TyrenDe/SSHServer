using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SSHServer.Packets
{
    public abstract class Packet
    {
        // https://tools.ietf.org/html/rfc4253#section-6.1
        public const int MaxPacketSize = 35000;

        public const int PacketHeaderSize = 5;

        public abstract PacketType PacketType { get; }

        public uint PacketSequence { get; set; }

        public static readonly Dictionary<PacketType, Type> PacketTypes = new Dictionary<PacketType, Type>();

        static Packet()
        {
            var packets = Assembly.GetEntryAssembly().GetTypes().Where(t => typeof(Packet).IsAssignableFrom(t));
            foreach(var packet in packets)
            {
                try
                {
                    Packet packetInstance = Activator.CreateInstance(packet) as Packet;
                    Packet.PacketTypes[packetInstance.PacketType] = packet;
                }
                catch { }
            }
        }

        public byte[] GetBytes()
        {
            using (ByteWriter writer = new ByteWriter())
            {
                writer.WritePacketType(PacketType);
                InternalGetBytes(writer);
                return writer.ToByteArray();
            }
        }

        public abstract void Load(ByteReader reader);
        protected abstract void InternalGetBytes(ByteWriter writer);
    }
}
