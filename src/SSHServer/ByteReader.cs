using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSHServer
{
    public class ByteReader : IDisposable
    {
        private readonly char[] ListSeparator = new char[] { ',' };
        private MemoryStream m_Stream;

        public bool IsEOF
        {
            get
            {
                if (disposedValue)
                    throw new ObjectDisposedException("ByteReader");

                return m_Stream.Position == m_Stream.Length;
            }
        }

        public ByteReader(byte[] data)
        {
            m_Stream = new MemoryStream(data);
        }

        public byte[] GetBytes(int length)
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteReader");

            byte[] data = new byte[length];
            m_Stream.Read(data, 0, length);
            return data;
        }

        public byte[] GetMPInt()
        {
            uint size = GetUInt32();

            if (size == 0)
                return new byte[1];

            byte[] data = GetBytes((int)size);
            if (data[0] == 0)
                return data.Skip(1).ToArray();

            return data;
        }

        public uint GetUInt32()
        {
            byte[] data = GetBytes(4);
            if (BitConverter.IsLittleEndian)
                data = data.Reverse().ToArray();
            return BitConverter.ToUInt32(data, 0);
        }

        public string GetString()
        {
            return GetString(Encoding.ASCII);
        }

        public string GetString(Encoding encoding)
        {
            int length = (int)GetUInt32();

            if (length == 0)
                return string.Empty;

            return encoding.GetString(GetBytes(length));
        }

        public List<string> GetNameList()
        {
            List<string> data = new List<string>();

            return new List<string>(GetString().Split(ListSeparator, StringSplitOptions.RemoveEmptyEntries));
        }

        public bool GetBoolean()
        {
            return (GetByte() != 0);
        }


        public byte GetByte()
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteReader");

            return (byte)m_Stream.ReadByte();
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
