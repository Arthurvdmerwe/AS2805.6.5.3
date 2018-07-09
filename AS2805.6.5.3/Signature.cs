using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    public class Signature
    {

        public byte[] SignData(byte[] msgBytes, RsaKeyParameters privKey)
        {
            try
            {
          
                ISigner signer = SignerUtilities.GetSigner("SHA-256withRSAandMGF1");
                signer.Init(true, privKey);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                byte[] sigBytes = signer.GenerateSignature();

                return sigBytes;
            }
            catch (Exception exc)
            {
                Console.WriteLine("Signing Failed: " + exc.ToString());
                return null;
            }
        }

        public bool VerifySignature(RsaKeyParameters pubKey, byte[] sigBytes, byte[] msgBytes)
        {
            try
            {
                ISigner signer = SignerUtilities.GetSigner("SHA-256withRSAandMGF1");
                signer.Init(false, pubKey);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                return signer.VerifySignature(sigBytes);
            }
            catch (Exception exc)
            {
                Console.WriteLine("Verification failed with the error: " + exc.ToString());
                return false;
            }
        }
    }
}
