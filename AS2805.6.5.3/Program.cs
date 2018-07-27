using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    class Program
    {


        static void Main(string[] args)
        {
            Console.WriteLine("Please select option 1/2");

            string option = Console.ReadLine();
            if (option == "1")
            {
                Certificate cert = new Certificate(2048);

                Console.WriteLine("---------------------------- AS2805.6.5.3 Option 1--------------------------------------------------------");



                Console.WriteLine("---------------Manufacturer’s key pair (PKman, SKman)---------------");
                Certificate man = new Certificate(2048);
                byte[] PKman = man.GetPublicKey();
                byte[] SKman = man.GetPrivateKey();


                Console.WriteLine("------------------Terminal cryptographic unit’s key pair (PKtcu, SKtcu)-------------------");
                Certificate tcu = new Certificate(2048);
                byte[] PKtcu = tcu.GetPublicKey();
                byte[] SKtcu = tcu.GetPrivateKey();

                Console.WriteLine("----------------Sponsor’s key pair (PKsp, SKsp)------------------------");
                Certificate sp = new Certificate(2048);
                byte[] PKsp = sp.GetPublicKey();
                byte[] SKsp = sp.GetPrivateKey();

                Console.WriteLine("--------------Getting RNsp, tcuid and user data -------------- ");
                Random rnd = new Random();
                string RNsp = rnd.Next(222222, 999999).ToString();
                byte[] RNsp_bytes = Encoding.ASCII.GetBytes(RNsp);
                Console.WriteLine("RNsp: \t" + RNsp);

                string user_data = "OPTIONAL USER DATA THAT CAN BE ANY LENGTH";
                byte[] user_data_bytes = Encoding.ASCII.GetBytes(user_data);
                Console.WriteLine("User Data: \t" + user_data);

                string tcuid = "MN044712H";
                byte[] tcuid_bytes = Encoding.ASCII.GetBytes(tcuid);
                Console.WriteLine("TCUID: \t" + tcuid);


                string AIIC = "0000045127823121";
                byte[] AIIC_bytes = Encoding.ASCII.GetBytes(AIIC);
                Console.WriteLine("AIIC: \t" + AIIC);


                SecureRandom random = new SecureRandom();
                DesEdeKeyGenerator keyGen = new DesEdeKeyGenerator();
                keyGen.Init(new KeyGenerationParameters(random, 128));

                byte[] KI_bytes = keyGen.GenerateKey();
                string KI = BitConverter.ToString(KI_bytes).Replace("-", string.Empty);
                Console.WriteLine("KI: \t" + KI);


                byte[] KIA_bytes = keyGen.GenerateKey();

                string KIA = BitConverter.ToString(KIA_bytes).Replace("-", string.Empty);
                Console.WriteLine("KIA: \t" + KIA);




                byte[] KCA_bytes = keyGen.GenerateKey();
                string KCA = BitConverter.ToString(KCA_bytes).Replace("-", string.Empty);
                Console.WriteLine("KCA: \t" + KCA);

                DateTime today = DateTime.Now.Date;
                byte[] today_bytes = Encoding.ASCII.GetBytes(today.ToString("yyyyMMdd HH:mm:ss"));
                Console.WriteLine("DTS: \t" + today.ToString("yyyyMMdd HH:mm:ss"));



                Console.WriteLine("-----------------------------------------------------------------------");


                Console.WriteLine("--------------------------Sponsor Pre-Compute--------------------------");
                HashMAC hash = new HashMAC(new Sha256Digest());
                byte[] H_PKman_userdata = hash.Hash_Data(PKman.Concat(user_data_bytes).ToArray());
                Console.WriteLine("SHA256 Hash of PKman + user data : \n" + Utils.HexDump(H_PKman_userdata));

                byte[] H_PKsp_RNsp_userdata = hash.Hash_Data(PKsp.Concat(RNsp_bytes).Concat(user_data_bytes).ToArray());
                //Console.WriteLine("SHA256 Hash of PKsp + user data : \n" + Utils.HexDump(H_PKman_userdata));

                Console.WriteLine("----------------------------------------------------------------------------------");
                Signature sign = new Signature();
                byte[] sSKman_H_PKman_userdata = sign.SignData(H_PKman_userdata, man.get_Private_Params());
                Console.WriteLine("Sponsor Verifies Manufacturer Signature of sSKman(H(PKman + user data)) : \n" + Utils.HexDump(sSKman_H_PKman_userdata));


                byte[] sSKman_H_PKsp_RNsp_userdata = sign.SignData(H_PKsp_RNsp_userdata, man.get_Private_Params());
                //Console.WriteLine("Signature of sSKman(H(PKsp + user data)) : \n" + Utils.HexDump(sSKman_H_PKsp_userdata));

                byte[] H_PKsp = hash.Hash_Data(PKsp);
                //Console.WriteLine("SHA256 Hash of PKsp : \n" + Utils.HexDump(H_PKsp));

                byte[] sSKman_H_PKsp = sign.SignData(H_PKsp, man.get_Private_Params());
                //Console.WriteLine("Signature of sSKman(H(PKsp))) : \n" + Utils.HexDump(sSKman_H_PKsp));

                //Console.WriteLine("--------------------------TCU Pre-Compute--------------------------");


                byte[] H_PKtcu = hash.Hash_Data(PKtcu);
                //Console.WriteLine("SHA256 Hash of PKtcu : \n" + Utils.HexDump(H_PKtcu));

                //Pad pad = new Pad();
                //var padHash = pad.Pad_Data(H_PKtcu, 128);
                //Console.WriteLine("SHA256 Hash of PKtcu and PKCS v1.5 padding : \n" + Utils.HexDump(padHash));
                Console.WriteLine("----------------------------------------------------------------------------------");
                byte[] sSKman_H_PKtcu_ = sign.SignData(H_PKtcu, man.get_Private_Params());
                Console.WriteLine("Termninal Verifies Manufacturer Signature of PKtcu sSKman(H(PKtcu)) :\n" + Utils.HexDump(sSKman_H_PKtcu_));
                Console.WriteLine("----------------------------------------------------------------------------------");

                byte[] sSKman_H_PKtcu_TCUID_userdata = sign.SignData(H_PKtcu.Concat(tcuid_bytes).Concat(user_data_bytes).ToArray(), man.get_Private_Params());
                //Console.WriteLine("Signature of sSKman(H(PKtcu)|TCUID|user data) : \n" + Utils.HexDump(sSKman_H_PKtcu));
                //Console.ReadLine();


                Console.WriteLine("-------------------------- OPTION 1 --------------------------");


                Console.WriteLine("--------------------------SIGN ON REQUEST 1--------------------------\n\n");
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("TCU -> Sending:...");
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("User Data: " + user_data + "\n" + Utils.HexDump(user_data_bytes));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("TCUID: " + tcuid + " \n" + Utils.HexDump(tcuid_bytes));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("H(PKtcu) \n" + Utils.HexDump(H_PKtcu));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("sSKman(H(PKtcu)|TCUID|user data) \n" + Utils.HexDump(sSKman_H_PKtcu_TCUID_userdata));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("------------------------SIGN ON RESPONSE 1--------------------------------------");
                Console.WriteLine("Veryfying Signature of sSKman(H(PKtcu)|TCUID|user data)");
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("User Data: " + user_data + "\n" + Utils.HexDump(user_data_bytes));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("RNsp: " + RNsp + "\n" + Utils.HexDump(RNsp_bytes));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("H(PKsp|RNsp|userdata) \n" + Utils.HexDump(H_PKsp_RNsp_userdata));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("Sign: sSKman(H(PKsp|RNsp|user data)):\n" + Utils.HexDump(sSKman_H_PKsp_RNsp_userdata));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("-------------------------- SIGN ON REQUEST 2--------------------------\n\n");
                //Construct cryptogram encrypted by PKsp 
                Console.WriteLine("Constructing the KI KeyBlock cryptogram (KI, TCUID, RNsp, DTS, user dat)----------");
                Asn1 asn = new Asn1();

                byte[] KI_KeyBlock_bytes = asn.KI_KeyBlock(KI_bytes, tcuid_bytes, today_bytes, RNsp_bytes, user_data_bytes);
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine(Utils.HexDump(KI_KeyBlock_bytes));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("Encrypt: ePKsp(KI, TCUID, RNsp, DTS, user data): \n");
                byte[] PKsp_KI_TCUID_RNsp_DTS_user_data = sp.Encrypt(KI_KeyBlock_bytes);
                Console.WriteLine(Utils.HexDump(PKsp_KI_TCUID_RNsp_DTS_user_data));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("Hash: H(ePKsp(KI, TCUID, RNsp, DTS, user data)): \n");
                byte[] H_PKsp_KI_TCUID_RNsp_DTS_user_data = hash.Hash_Data(PKsp_KI_TCUID_RNsp_DTS_user_data);
                Console.WriteLine(Utils.HexDump(H_PKsp_KI_TCUID_RNsp_DTS_user_data));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("Sign: sSKtcu(H(ePKsp(KI, TCUID, RNsp, DTS, user data))): \n");
                byte[] sSKtcu_H_PKsp_KI_TCUID_RNsp_DTS_user_data = sign.SignData(H_PKsp_KI_TCUID_RNsp_DTS_user_data, tcu.get_Private_Params());
                Console.WriteLine(Utils.HexDump(sSKtcu_H_PKsp_KI_TCUID_RNsp_DTS_user_data));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("Send Signature and Encryption to Sponsor so that KI can be extracted \n");
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("Verify: sSKtcu(H(ePKsp(KI, TCUID, RNsp, DTS, user data))): \n");
                bool sSKtcuV = sign.VerifySignature(tcu.get_Public_Params(), sSKtcu_H_PKsp_KI_TCUID_RNsp_DTS_user_data, H_PKsp_KI_TCUID_RNsp_DTS_user_data);
                Console.WriteLine("Verified: " + sSKtcuV);
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("Decrypt: ePKsp(KI, TCUID, RNsp, DTS, user data): \n");
                Console.WriteLine("Decrypted:\n" + Utils.HexDump(sp.Decrypt(PKsp_KI_TCUID_RNsp_DTS_user_data)));
                Console.WriteLine("----------------------------------------------------------------------------------\n\n");

                Console.WriteLine("--------------------------  SIGN ON RESPONSE 2-------------------------\n\n");
                /*
                 The KCA shall be used to derive a unique KIA_n per acquirer. The sponsor shall be responsible for providing the KIA_n to each acquirer through a secure channel. 
                 Each acquirer shall use its unique KIAn to download or derive the initial key(s) required for the appropriate key management scheme


                The AIIC is right justified and left zero filled in a 128-bit data field.
                    KMACI_n = (OWF(KIA_n,D))
                    KCA = 
                 */
                DESAES desaes = new DESAES();


                Console.WriteLine("-------------------------Calculate KMACI_n = HMAC(KIA_n,AIIC) -------------------------\n");
                Console.WriteLine("-------------------------OWF = SHA256 HMAC -------------------------");
                byte[] H_KIA_n_AIIC = hash.HMAC(AIIC_bytes, KIA_bytes);
                Console.WriteLine("KMAC = \n" + Utils.HexDump(H_KIA_n_AIIC));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("KCA = \n" + Utils.HexDump(KCA_bytes));
                Console.WriteLine("------------------------------ENCRYPT---------------------------------------------");
                var E_KMAC = desaes.EncryptDES3(H_KIA_n_AIIC, KI_bytes);
                Console.WriteLine("e(KMAC) = \n" + Utils.HexDump(E_KMAC));
                Console.WriteLine("----------------------------------------------------------------------------------");
                var E_KCA = desaes.EncryptDES3(KCA_bytes, KI_bytes);
                Console.WriteLine("e(KCA) = \n" + Utils.HexDump(E_KCA));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("------------------------------DECRYPT---------------------------------------------");
                var D_KCA = desaes.DecryptDES3(E_KCA, KI_bytes);
                Console.WriteLine("d(KCA) = \n" + Utils.HexDump(D_KCA));
                Console.WriteLine("----------------------------------------------------------------------------------");
                var D_KMAC = desaes.DecryptDES3(E_KMAC, KI_bytes);
                Console.WriteLine("d(KMAC) = \n" + Utils.HexDump(D_KMAC));
                Console.WriteLine("----------------------------------------------------------------------------------");
                Console.WriteLine("**------------------------------DONE--------------------------------------------**");








            }
            else
            {

                bool ForEncryption = true;

                //Requested Certificate Name and things
                X509Name name = new X509Name("C=Commonwealth Bank of Australia, O=CBA, OU=Cryptographical Services, CN=TID25124548");
     


                //Key generation 2048bits
                var rkpg = new RsaKeyPairGenerator();
                rkpg.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
                AsymmetricCipherKeyPair ackp = rkpg.GenerateKeyPair(); //BAPI.EncryptionKey;
                                                                       //if (!ForEncryption) ackp = BAPI.SignKey;

                //Key Usage Extension
                var ku = new KeyUsage(ForEncryption ? KeyUsage.KeyEncipherment : KeyUsage.DigitalSignature);
                var extgen = new Org.BouncyCastle.Asn1.X509.X509ExtensionsGenerator();
                extgen.AddExtension(X509Extensions.KeyUsage, true, ku);
                var attribute = new AttributeX509(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extgen.Generate()));

                //PKCS #10 Certificate Signing Request
                Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest("SHA1WITHRSA", name, ackp.Public, new DerSet(attribute), ackp.Private); //new DerSet(new DerOctetString(ku))

                var csrbytedata = csr.GetDerEncoded();
            
                var asn1Csr = csr.ToAsn1Object();
                //////
                Console.WriteLine(asn1Csr.GetDerEncoded().ToString());
                Console.WriteLine(Utils.HexDump(csrbytedata));
                string pwd = "password";
                var suppliers = new[] { "CN=*.cba.com.au" };

                var CA_issuer = new X509(suppliers, "CN=CBA RootCA, OU=Cryptographical Services, O=Commonwealth Bank of Australia, L=SYDNEY, C=AU", CertStrength.bits_2048);
                X509Certificate2 GeneratedCert = CA_issuer.MakeCertificate(pwd, "CN=TID25124548.cba.com.au, OU=Commonwealth Bank of Australia, OU=CBA Business System Hosting, O=Commonwealth Bank of Australia, C=AU", 2);
               
                Console.WriteLine(GeneratedCert.ToString());
                Console.WriteLine(Utils.HexDump(GeneratedCert.Export(X509ContentType.Pkcs12, pwd)));
               
                Console.ReadLine();
          
            }

        }
    }
}
