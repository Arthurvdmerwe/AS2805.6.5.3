using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    public class Asn1
    {
        //ASN1Primitggggg
        Asn1Sequence asn1;
        public Asn1(Asn1TaggedObject obj)
        {
      
        }

        public Asn1()
        {

        }

        public Asn1Object AddObject(string oid, byte[] enc)
        {
            DerObjectIdentifier o = new DerObjectIdentifier(oid);
            var der = DerBitString.GetInstance(o);
          

            DerBitString s1 = new DerBitString(enc, 0);
            
            
            Asn1Object encO = Asn1Object.FromByteArray(s1.GetEncoded());
         

            return encO;
            
        }


        public byte[] SHA256_DER(byte[] message)
        {


            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"));
            v.Add(new DerOctetString(message));
            var s = new DerSequence(v);
            DumpASN(s);
            return s.GetEncoded();

        }

        public byte[] KI_KeyBlock(byte[] KI, byte[] TCUID, byte[] DTS, byte[] RNsp, byte[] user_data)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(new DerOctetString(KI));
            v.Add(new DerOctetString(TCUID));
            v.Add(new DerOctetString(DTS));
            v.Add(new DerOctetString(RNsp));
            v.Add(new DerOctetString(user_data));
            var s = new DerSequence(v);
            DumpASN(s);
            return s.GetEncoded();
        }


        public void DumpASN(Asn1Encodable DERasn1)
        {
            Console.WriteLine(Asn1Dump.DumpAsString(DERasn1));
        }

    }
}
