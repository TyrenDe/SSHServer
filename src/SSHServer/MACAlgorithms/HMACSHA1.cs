using SSHServer.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.MACAlgorithms
{
    public class HMACSHA1 : IMACAlgorithm
    {
        System.Security.Cryptography.HMACSHA1 m_HMAC = null;

        public uint DigestLength
        {
            get
            {
                // https://tools.ietf.org/html/rfc4253#section-6.4
                // According to this, the DigestLength is 20
                return 20;
            }
        }

        public uint KeySize
        {
            get
            {
                // https://tools.ietf.org/html/rfc4253#section-6.4
                // According to this, the KeySize is 20
                return 20;
            }
        }

        public string Name
        {
            get
            {
                return "hmac-sha1";
            }
        }

        public byte[] ComputeHash(uint packetNumber, byte[] data)
        {
            if (m_HMAC == null)
                throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "SetKey must be called before attempting to ComputeHash.");

            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteUInt32(packetNumber);
                writer.WriteRawBytes(data);
                return m_HMAC.ComputeHash(writer.ToByteArray());
            }
        }

        public void SetKey(byte[] key)
        {
            m_HMAC = new System.Security.Cryptography.HMACSHA1(key);
        }
    }
}
