using SSHServer.Packets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSHServer
{
    public class ByteWriter : IDisposable
    {
        private MemoryStream m_Stream = new MemoryStream();

        public void WritePacketType(PacketType packetType)
        {
            WriteByte((byte)packetType);
        }

        public void WriteBytes(byte[] value)
        {
            WriteUInt32((uint)value.Count());
            WriteRawBytes(value);
        }

        public void WriteString(string value)
        {
            WriteString(value, Encoding.ASCII);
        }

        public void WriteString(string value, Encoding encoding)
        {
            WriteBytes(encoding.GetBytes(value));
        }

        public void WriteStringList(IEnumerable<string> list)
        {
            WriteString(string.Join(",", list));
        }

        public void WriteUInt32(uint value)
        {
            byte[] data = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                data = data.Reverse().ToArray();
            WriteRawBytes(data);
        }

        public void WriteMPInt(byte[] value)
        {
            if ((value.Length == 1) && (value[0] == 0))
            {
                WriteUInt32(0);
                return;
            }

            uint length = (uint)value.Length;
            if (((value[0] & 0x80) != 0))
            {
                WriteUInt32((uint)(length + 1));
                WriteByte(0x00);
            }
            else
            {
                WriteUInt32((uint)length);
            }

            WriteRawBytes(value);
        }

        public void WriteRawBytes(byte[] value)
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteWriter");
            m_Stream.Write(value, 0, value.Count());
        }

        public void WriteByte(byte value)
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteWriter");
            m_Stream.WriteByte(value);
        }

        public byte[] ToByteArray()
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteWriter");
            return m_Stream.ToArray();
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    m_Stream.Dispose();
                    m_Stream = null;
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
