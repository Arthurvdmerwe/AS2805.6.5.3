using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    class Program
    {




        //Generate a publuc private key p[air
        //Hash abd sign the public keys 'SHA256
        static void Main(string[] args)
        {
            Certificate cert = new Certificate(2048);

            Console.WriteLine(" ---------------------------- AS2805.6.5.3 --------------------------------------------------------");
            


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
            Console.WriteLine("RNsp: " + RNsp_bytes);

            string user_data = "OPTIONAL USER DATA THAT CAN BE ANY LENGTH";
            byte[] user_data_bytes = Encoding.ASCII.GetBytes(user_data);
            Console.WriteLine("User Data: " + user_data);

            string tcuid = "MN044712H";
            byte[] tcuid_bytes = Encoding.ASCII.GetBytes(tcuid);
            Console.WriteLine("TCUID: " + user_data);


         
            string KI = "123456789123456789";
            byte[] KI_bytes = Encoding.ASCII.GetBytes(KI);
            Console.WriteLine("KI: " + KI);

            string KCA = "123456789123456789";
            byte[] KCA_bytes = Encoding.ASCII.GetBytes(KCA);
            Console.WriteLine("KCA: " + KCA);

            DateTime today = DateTime.Now.Date;
            byte[] today_bytes = Encoding.ASCII.GetBytes(today.ToString("yyyyMMdd HH:mm:ss.FFF"));
            Console.WriteLine("DTS: " + today.ToString("yyyyMMdd HH:mm:ss.FFF"));



            Console.WriteLine("--------------Getting tcuid and user data --- FINISHED-------");


            Console.WriteLine("--------------------------Sponsor Pre-Compute--------------------------");
            HashMAC hash = new HashMAC(new Sha256Digest());
            byte[] H_PKman_userdata = hash.Hash_Data(PKman.Concat(user_data_bytes).ToArray());
            Console.WriteLine("SHA256 Hash of PKman + user data : \n" + Utils.HexDump(H_PKman_userdata));

            byte[] H_PKsp_userdata = hash.Hash_Data(PKsp.Concat(user_data_bytes).ToArray());
            Console.WriteLine("SHA256 Hash of PKsp + user data : \n" + Utils.HexDump(H_PKman_userdata));


            Signature sign = new Signature();
            byte[] sSKman_H_PKman_userdata = sign.SignData(H_PKman_userdata, man.get_Private_Params());
            Console.WriteLine("Signature of sSKman(H(PKman + user data)) : \n" + Utils.HexDump(sSKman_H_PKman_userdata));


            byte[] sSKman_H_PKsp_userdata = sign.SignData(H_PKsp_userdata, man.get_Private_Params());
            Console.WriteLine("Signature of sSKman(H(PKsp + user data)) : \n" + Utils.HexDump(sSKman_H_PKsp_userdata));

            byte[] H_PKsp = hash.Hash_Data(PKsp);
            Console.WriteLine("SHA256 Hash of PKsp : \n" + Utils.HexDump(H_PKsp));
   
            byte[] sSKman_H_PKsp = sign.SignData(H_PKsp, man.get_Private_Params());
            Console.WriteLine("Signature of sSKman(H(PKman)) : \n" + Utils.HexDump(sSKman_H_PKsp));

            Console.WriteLine("--------------------------TCU Pre-Compute--------------------------");


            byte[] H_PKtcu = hash.Hash_Data(PKtcu);
            Console.WriteLine("SHA256 Hash of PKtcu : \n" + Utils.HexDump(H_PKtcu));

            Pad pad = new Pad();
            var padHash = pad.Pad_Data(H_PKtcu, 128);
            Console.WriteLine("SHA256 Hash of PKtcu and PKCS v1.5 padding : \n" + Utils.HexDump(padHash));
            


            byte[] sSKman_H_PKtcu = sign.SignData(H_PKtcu, man.get_Private_Params());
            Console.WriteLine("Signature of sSKman(H(PKtcu)) : \n" + Utils.HexDump(sSKman_H_PKtcu));
            //Console.ReadLine();


            Console.WriteLine("-------------------------- OPTION 1 --------------------------");


            Console.WriteLine("-------------------------- Initlize sign-on request 1--------------------------\n\n");
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("TCU -> Sending:...");
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("User Data: " + user_data + "\n" + Utils.HexDump(user_data_bytes));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("TCUID: "+ tcuid + " \n" + Utils.HexDump(tcuid_bytes));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("H(PKtcu) \n" + Utils.HexDump(H_PKtcu));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("sSKman(H(PKtcu)) \n" + Utils.HexDump(sSKman_H_PKtcu));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("****.....Sponsor Calculating:...");
            Console.WriteLine("Storing TCUID & User Data");
            Console.WriteLine("Veryfying Signature of sSKman(H(PKtcu))");
            Console.WriteLine("-------------------------- Initlize sign-on response 1--------------------------\n\n");
            Console.WriteLine("Sponsor Calculating...and Sending");
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("H(PKsp) \n" + Utils.HexDump(H_PKsp));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("H(PKsp + user data) \n" + Utils.HexDump(H_PKsp_userdata));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("User Data: " + user_data + "\n" + Utils.HexDump(user_data_bytes));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("RNsp: " + RNsp + "\n" + Utils.HexDump(RNsp_bytes));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("Sign: sSKman(H(PKsp, user data)):\n" + Utils.HexDump(sSKman_H_PKsp_userdata));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("-------------------------- Initlize sign-on request 2--------------------------\n\n");
            //Construct cryptogram encrypted by PKsp 
            Console.WriteLine("Constructing the KI KeyBlock cryptogram (KI, TCUID, RNsp, DTS, user dat)----------");
            Asn1 asn = new Asn1();
            
            byte[] KI_KeyBlock_bytes = asn.KI_KeyBlock(KI_bytes, tcuid_bytes, today_bytes, RNsp_bytes, user_data_bytes);
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine(Utils.HexDump(KI_KeyBlock_bytes));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("Encrypt: ePKsp(KI, TCUID, RNsp, DTS, user data): \n");
            byte[] PKsp_KI_TCUID_RNsp_DTS_user_data =  sp.Encrypt(KI_KeyBlock_bytes);
            Console.WriteLine(Utils.HexDump(PKsp_KI_TCUID_RNsp_DTS_user_data));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("Hash: H(ePKsp(KI, TCUID, RNsp, DTS, user data)): \n");
            byte[] H_PKsp_KI_TCUID_RNsp_DTS_user_data =  hash.Hash_Data(PKsp_KI_TCUID_RNsp_DTS_user_data);
            Console.WriteLine(Utils.HexDump(H_PKsp_KI_TCUID_RNsp_DTS_user_data));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("Sign: sSKtcu(H(ePKsp(KI, TCUID, RNsp, DTS, user data))): \n");
            byte[] sSKtcu_H_PKsp_KI_TCUID_RNsp_DTS_user_data = sign.SignData(H_PKsp_KI_TCUID_RNsp_DTS_user_data, tcu.get_Private_Params());
            Console.WriteLine(Utils.HexDump(sSKtcu_H_PKsp_KI_TCUID_RNsp_DTS_user_data));
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("Send Signature and Encryption to Sponsor so that KI can be extracted \n");
            Console.WriteLine("--------------------------  SIGN ON RESPONSE 2-------------------------\n\n");
       


            Console.WriteLine("-------------------------- DONE--------------------------\n\n");


            Console.ReadLine();
         
            //var obj = asn.AddObject(NistObjectIdentifiers.IdSha256.Id, H_PKman_userdata);
            //obj.ToString();

            //var obj = asn.SHA256_DER(H_PKman_userdata);
            //Console.WriteLine("----");
            //Console.WriteLine(Utils.HexDump(obj));
            //Console.WriteLine("----");
            //Console.WriteLine(BitConverter.ToString(obj).Replace("-", string.Empty));


            //byte[] KI = Encoding.ASCII.GetBytes("5645645456446554564544564564651233212154534535343");
            //byte[] TCUID = tcuid_bytes;
            
            //byte[] RNsp_bytes2 = RNsp_bytes;
            //byte[] User_Data = user_data_bytes;

            //Console.WriteLine("--Constructing the KI KeyBlock---");
            //Console.WriteLine("KIKeyBlock = Sequence { KI OCTET STRING,");
            //Console.WriteLine("\tTCUID           OCTET STRING,");
            //Console.WriteLine("\tDTS             OCTET STRING,");
            //Console.WriteLine("\tRNsp            OCTET STRING,");
            //Console.WriteLine("\tUserData        OCTET STRING} ");
            //Console.WriteLine("--KI KeyBlock Binary Dump---");
            //var KI_KeyBlock = asn.KI_KeyBlock(KI, TCUID, DTS, RNsp_bytes2, User_Data);
            //Console.WriteLine("----");
            //Console.WriteLine(Utils.HexDump(KI_KeyBlock));
            //Console.WriteLine("----");
            //Console.WriteLine("KI KeyBlock HEX String");
            //Console.WriteLine(BitConverter.ToString(KI_KeyBlock).Replace("-", string.Empty));
            //Console.WriteLine("----");
            //Console.ReadLine();


            //Hash hash = new Hash(new Sha256Digest());
            // //cert.Test_Function();
            // byte[] pubKey = cert.GetPublicKey();
            // byte[] priKey = cert.GetPrivateKey();

            // byte[] hashed = hash.Hash_Data(pubKey);
            // Console.WriteLine("SHA256 Hash of Public Key: \n" + Utils.HexDump(hashed));
            // Signature sign = new Signature();
            // byte[] signature = sign.SignData(hashed, man.get_Private_Params());

            // Console.WriteLine("Sign the Hash: \n" + Utils.HexDump(signature));



            // Console.WriteLine("Please enter Text to Encrypt");
            // string input = Console.ReadLine();
            // byte[] cypher = cert.Encrypt(input);
            // Console.WriteLine("Encrypted Data: " + cypher);
            // string decypher = cert.Decrypt(cypher);
            // Console.WriteLine("Decrypted Data: " + decypher);
            // Console.ReadLine();

        }
    }
}
