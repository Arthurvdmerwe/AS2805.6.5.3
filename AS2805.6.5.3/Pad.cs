using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AS2805._6._5._3
{
    public class Pad
    {

        public byte[] Pad_Data(byte[] data, int length)
        {
            //0x00 | 0x02 | random non zero padding bytes | 0x00 | original message
            
            length = length;
            string hex = BitConverter.ToString(data).Replace("-", string.Empty);
            string nothing = "";
            hex = "0002" + nothing.PadLeft(length - data.Length, 'F') + "00" + hex;
            var new_data = Utils.HexStringToByteArray(hex);
            return new_data;

        }

    }
}
