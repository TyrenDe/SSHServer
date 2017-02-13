using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SSHServer.KexAlgorithms
{
    public class DiffieHellmanGroup14SHA1 : IKexAlgorithm
    {
        // http://tools.ietf.org/html/rfc3526 - 2048-bit MODP Group
        private const string MODPGroup2048 = "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
        private static readonly BigInteger s_P;
        private static readonly BigInteger s_G;

        private readonly BigInteger m_Y;

        private readonly SHA1 m_HashAlgorithm = SHA1.Create();

        // The following steps are used to exchange a key. In this:
        //    C is the client
        //    S is the server
        //    p is a large safe prime (RFC 3526)
        //    g is a generator (RFC 3526)
        // For a subgroup of GF(p); q is the order of the subgroup; V_S is S's
        // identification string; V_C is C's identification string; K_S is S's
        // public host key; I_C is C's SSH_MSG_KEXINIT message and I_S is S's
        // SSH_MSG_KEXINIT message that have been exchanged before this part
        // begins.

        public string Name
        {
            get
            {
                return "diffie-hellman-group14-sha1";
            }
        }

        static DiffieHellmanGroup14SHA1()
        {
            //    p is a large safe prime (RFC 3526)
            s_P = BigInteger.Parse(MODPGroup2048, NumberStyles.HexNumber);

            //    g is a generator (RFC 3526)
            s_G = new BigInteger(2);
        }

        public DiffieHellmanGroup14SHA1()
        {
            // 2. S generates a random number y (0 < y < q) 
            var bytes = new byte[80]; // 80 * 8 = 640 bits
            RandomNumberGenerator.Create().GetBytes(bytes);
            m_Y = BigInteger.Abs(new BigInteger(bytes));
        }

        public byte[] CreateKeyExchange()
        {
            //  and computes: f = g ^ y mod p.
            BigInteger keyExchange = BigInteger.ModPow(s_G, m_Y, s_P);
            byte[] key = keyExchange.ToByteArray();
            if (BitConverter.IsLittleEndian)
                key = key.Reverse().ToArray();

            if ((key.Length > 1) && (key[0] == 0x00))
            {
                key = key.Skip(1).ToArray();
            }

            return key;
        }

        public byte[] DecryptKeyExchange(byte[] keyEx)
        {
            // https://tools.ietf.org/html/rfc4253#section-8
            // 1. C generates a random number x (1 < x < q) and computes
            //    e = g ^ x mod p.  C sends e to S.

            // S receives e.  It computes K = e^y mod p,
            if (BitConverter.IsLittleEndian)
                keyEx = keyEx.Reverse().ToArray();

            BigInteger e = new BigInteger(keyEx.Concat(new byte[] { 0 }).ToArray());
            byte[] decrypted = BigInteger.ModPow(e, m_Y, s_P).ToByteArray();
            if (BitConverter.IsLittleEndian)
                decrypted = decrypted.Reverse().ToArray();

            if ((decrypted.Length > 1) && (decrypted[0] == 0x00))
            {
                decrypted = decrypted.Skip(1).ToArray();
            }

            return decrypted;
        }

        public byte[] ComputeHash(byte[] value)
        {
            // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
            return m_HashAlgorithm.ComputeHash(value);
        }
    }
}
