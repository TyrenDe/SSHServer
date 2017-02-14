using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSHServer.Packets
{
    public class Disconnect : Packet
    {
        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_DISCONNECT;
            }
        }

        public DisconnectReason Reason { get; set; }
        public string Description { get; set; }
        public string Language { get; set; } = "en";

        public override void Load(ByteReader reader)
        {
            Reason = (DisconnectReason)reader.GetUInt32();
            Description = reader.GetString(Encoding.UTF8);
            if (!reader.IsEOF)
                Language = reader.GetString();
        }

        protected override void InternalGetBytes(ByteWriter writer)
        {
            writer.WriteUInt32((uint)Reason);
            writer.WriteString(Description, Encoding.UTF8);
            writer.WriteString(Language);
        }
    }
}
