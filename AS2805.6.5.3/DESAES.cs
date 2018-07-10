using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    public class DESAES
    {

        public byte[] EncryptDES3(byte[] message,byte[] key)
        {
            DesEdeEngine desedeEngine = new DesEdeEngine();
            BufferedBlockCipher bufferedCipher = new BufferedBlockCipher(desedeEngine);

            // Create the KeyParameter for the DES3 key generated. 
            KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DESEDE", key);
            byte[] output = new byte[bufferedCipher.GetOutputSize(message.Length)];
            bufferedCipher.Init(true, keyparam);
            output = bufferedCipher.DoFinal(message);
            return output;
        }

        public byte[] DecryptDES3(byte[] message, byte[] key)
        {
            DesEdeEngine desedeEngine = new DesEdeEngine();
            BufferedBlockCipher bufferedCipher = new BufferedBlockCipher(desedeEngine);

            // Create the KeyParameter for the DES3 key generated. 
            KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DESEDE", key);
            byte[] output = new byte[bufferedCipher.GetOutputSize(message.Length)];
            bufferedCipher.Init(false, keyparam);
            output = bufferedCipher.DoFinal(message);
            return output;
        }

        public byte[] EncryptDES3_CBC(byte[] message, byte[] key)
        {
            DesEdeEngine desedeEngine = new DesEdeEngine();
            BufferedBlockCipher bufferedCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(desedeEngine));
            KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DESEDE", key);
            byte[] output = new byte[bufferedCipher.GetOutputSize(message.Length)];
            bufferedCipher.Init(true, keyparam);
            output = bufferedCipher.DoFinal(message);
            return output;
        }

        public byte[] DecryptDES3_CBC(byte[] message, byte[] key)
        {
            DesEdeEngine desedeEngine = new DesEdeEngine();
            BufferedBlockCipher bufferedCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(desedeEngine));
            KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DESEDE", key);
            byte[] output = new byte[bufferedCipher.GetOutputSize(message.Length)];
            bufferedCipher.Init(false, keyparam);
            output = bufferedCipher.DoFinal(message);
            return output;
        }


        public byte[] AESEncryption(byte[] message, byte[] iVector, byte[] mKey)
        {
    
            KeyParameter aesKeyParam = ParameterUtilities.CreateKeyParameter("AES", mKey);

            // Setting up the Initialization Vector. IV is used for encrypting the first block of input   message
            ParametersWithIV aesIVKeyParam = new ParametersWithIV(aesKeyParam, iVector);

            // Create the cipher object for AES algorithm using CFB mode and No Padding.
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CFB/NoPadding");
            cipher.Init(true, aesIVKeyParam);
            byte[] output = cipher.DoFinal(message);

            return output;
        }

        public byte[] AESDecryption(byte[] message, byte[] iVector, byte[] m_Key)
        {

            KeyParameter aesKeyParam = ParameterUtilities.CreateKeyParameter("AES", m_Key);

            // Setting up the Initialization Vector. IV is used for encrypting the first block of input   message
            ParametersWithIV aesIVKeyParam = new ParametersWithIV(aesKeyParam, iVector);

            // Create the cipher object for AES algorithm using CFB mode and No Padding.
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CFB/NoPadding");
            cipher.Init(true, aesIVKeyParam);
            byte[] output = cipher.DoFinal(message);

            return output;
        }
    }
}
