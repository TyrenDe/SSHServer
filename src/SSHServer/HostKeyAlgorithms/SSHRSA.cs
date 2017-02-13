using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Xml;

namespace SSHServer.HostKeyAlgorithms
{
    public class SSHRSA : IHostKeyAlgorithm
    {
        private readonly RSA m_RSA = RSA.Create();

        public string Name
        {
            get
            {
                return "ssh-rsa";
            }
        }

        public void ImportKey(string keyXml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(keyXml);

            XmlElement root = doc["RSAKeyValue"];

            RSAParameters p = new RSAParameters()
            {
                Modulus = Convert.FromBase64String(root["Modulus"].InnerText),
                Exponent = Convert.FromBase64String(root["Exponent"].InnerText),
                P = Convert.FromBase64String(root["P"].InnerText),
                Q = Convert.FromBase64String(root["Q"].InnerText),
                DP = Convert.FromBase64String(root["DP"].InnerText),
                DQ = Convert.FromBase64String(root["DQ"].InnerText),
                InverseQ = Convert.FromBase64String(root["InverseQ"].InnerText),
                D = Convert.FromBase64String(root["D"].InnerText)
            };

            m_RSA.ImportParameters(p);
        }

        public byte[] CreateKeyAndCertificatesData()
        {
            // The "ssh-rsa" key format has the following specific encoding:
            //      string    "ssh-rsa"
            //      mpint e
            //      mpint n
            RSAParameters parameters = m_RSA.ExportParameters(false);

            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteString(Name);
                writer.WriteMPInt(parameters.Exponent);
                writer.WriteMPInt(parameters.Modulus);
                return writer.ToByteArray();
            }
        }

        public byte[] CreateSignatureData(byte[] value)
        {
            // Signing and verifying using this key format is performed according to
            // the RSASSA-PKCS1-v1_5 scheme in [RFC3447] using the SHA-1 hash.
            // The resulting signature is encoded as follows:
            //      string    "ssh-rsa"
            //      string    rsa_signature_blob
            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteString(Name);
                writer.WriteBytes(m_RSA.SignData(value, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
                return writer.ToByteArray();
            }
        }
    }
}
