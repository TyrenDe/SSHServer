using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.Ciphers
{
    public class NoCipher : ICipher
    {
        public uint BlockSize
        {
            get
            {
                return 8;
            }
        }

        public uint KeySize
        {
            get
            {
                return 0;
            }
        }

        public string Name
        {
            get
            {
                return "none";
            }
        }

        public byte[] Decrypt(byte[] data)
        {
            return data;
        }

        public byte[] Encrypt(byte[] data)
        {
            return data;
        }

        public void SetKey(byte[] key, byte[] iv)
        {
            // No key for this cipher
        }
    }
}
