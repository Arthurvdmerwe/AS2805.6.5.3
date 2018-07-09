using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    public class HashMAC
    {
        IDigest hash;

        public HashMAC(IDigest _digest)
        {
            hash = _digest;
        }

        public byte[] Hash_Data(byte[] data)
        {
            hash.BlockUpdate(data, 0, data.Length);
            byte[] compArr = new byte[hash.GetDigestSize()];
            hash.DoFinal(compArr, 0);

            return compArr;
        }

        public byte[] HMAC(byte[] data, byte[] key)
        {
            var hmac = new HMac(new Sha256Digest());
            hmac.Init(new KeyParameter(key));
            byte[] result = new byte[hmac.GetMacSize()];
    
            hmac.BlockUpdate(data, 0, data.Length);
            hmac.DoFinal(result, 0);

            return result;
        }
    }
}
