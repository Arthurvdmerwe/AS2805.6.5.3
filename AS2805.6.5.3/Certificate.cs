using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    public class Certificate
    {
        RsaKeyPairGenerator rsaKeyPairGnr;
        SHA256Managed hash = new SHA256Managed();
        SecureRandom randomNumber = new SecureRandom();
        UTF8Encoding utf8enc = new UTF8Encoding();
        RsaKeyParameters privateKey;
        RsaKeyParameters publicKey;
        AsymmetricCipherKeyPair keyPair;
        IAsymmetricBlockCipher cipher;


        public Certificate(int rsaKeySize)
        {
            rsaKeyPairGnr = new RsaKeyPairGenerator();
       
            rsaKeyPairGnr.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), rsaKeySize));
            GeneratePair();
        }


        public byte[] GetPublicKey()
        {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
           
            Console.WriteLine("Public Key -> exported as ASN1.DER Encoded");
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            Console.WriteLine("Public Key: -> \n" + Utils.HexDump(serializedPublicBytes));
            Console.WriteLine("Public Key -> pad bits = " + publicKeyInfo.PublicKeyData.PadBits);
            Console.WriteLine("Public Key -> Exponent = " + publicKey.Exponent.ToString());
            //return BitConverter.ToString(serializedPublicBytes).Replace("-", string.Empty);
            return serializedPublicBytes;

        }

        public byte[] GetPrivateKey()
        {
            Console.WriteLine("Public Key -> exported as ASN1.DER Encoded");
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();
            Console.WriteLine("Private Key: -> \n" + Utils.HexDump(serializedPrivateBytes));
            Console.WriteLine("Private Key -> Modulus: \n" + Utils.HexDump(Utils.HexStringToByteArray(privateKey.Modulus.ToString())));
            Console.WriteLine("Private Key -> Exponent:\n" + Utils.HexDump(Utils.HexStringToByteArray(privateKey.Exponent.ToString())));
            string serializedPrivate = Convert.ToBase64String(serializedPrivateBytes);
            //return BitConverter.ToString(serializedPrivateBytes).Replace("-", string.Empty);
            return serializedPrivateBytes;
            //Convert.FromBase64String(serializedPrivate);
        }

        public RsaKeyParameters get_Private_Params()
        {

            RsaKeyParameters paramsDSA = (RsaKeyParameters)keyPair.Private;
            return paramsDSA;
        }

        public RsaKeyParameters get_Public_Params()
        {

            RsaKeyParameters paramsDSA = (RsaKeyParameters)keyPair.Public;
            return paramsDSA;
        }

        private void GeneratePair()
        {
            byte[] encodingParam = hash.ComputeHash(Encoding.UTF8.GetBytes(randomNumber.ToString()));
             keyPair = rsaKeyPairGnr.GenerateKeyPair();
             publicKey = (RsaKeyParameters)keyPair.Public;
             privateKey = (RsaKeyParameters)keyPair.Private;
             cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), encodingParam);
           

        }

        public byte[] Encrypt(byte[] message)
        {
            cipher.Init(true, publicKey);

            //byte[] message = utf8enc.GetBytes(messages);
            byte[] ciphered =  cipher.ProcessBlock(message, 0, message.Length);
            string cipheredText = utf8enc.GetString(ciphered);
            return ciphered;
        }
        public byte[] Decrypt(byte[] message)
        {

            cipher.Init(false, privateKey);
            //byte[] message = utf8enc.GetBytes(messages);
            byte[] deciphered = cipher.ProcessBlock(message, 0, message.Length);
            return deciphered;
        }



        public void Test_Function()
        {

        SHA256Managed hash = new SHA256Managed();
        SecureRandom randomNumber = new SecureRandom();
        byte[] encodingParam = hash.ComputeHash(Encoding.UTF8.GetBytes(randomNumber.ToString()));
        string inputMessage = "Test Message";
        UTF8Encoding utf8enc = new UTF8Encoding();


        byte[] inputBytes = utf8enc.GetBytes(inputMessage);


        RsaKeyPairGenerator rsaKeyPairGnr = new RsaKeyPairGenerator();
        rsaKeyPairGnr.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 1024));
        AsymmetricCipherKeyPair keyPair = rsaKeyPairGnr.GenerateKeyPair();
            
         publicKey = (RsaKeyParameters)keyPair.Public;
         privateKey = (RsaKeyParameters)keyPair.Private;
            //string pub = GetPublicKey();
            //string priv = GetPrivateKey();
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), encodingParam);

        cipher.Init(true, publicKey);
        byte[] ciphered = cipher.ProcessBlock(inputBytes, 0, inputMessage.Length);
        string cipheredText = utf8enc.GetString(ciphered);


        cipher.Init(false, privateKey);
        byte[] deciphered = cipher.ProcessBlock(ciphered, 0, ciphered.Length);
        string decipheredText = utf8enc.GetString(deciphered);

    }

    }
}
