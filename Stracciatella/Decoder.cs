using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stracciatella
{
    class Decoder
    {
        public static string Base64Decode(string input)
        {
            byte[] data = System.Convert.FromBase64String(input);
            string output = System.Text.ASCIIEncoding.ASCII.GetString(data);

            return output;
        }

        public static byte[] Base64DecodeBinary(string input)
        {
            return System.Convert.FromBase64String(input);
        }

        public static byte[] XorDecodeBinary(byte[] input, int key)
        {
            List<byte> outb = new List<byte>();
            byte ch;

            for (int i = 0; i < input.Length; i++)
            {
                ch = (byte)(input[i] ^ key);
                outb.Add(ch);
            }
            return outb.ToArray();
        }

        public static string XorDecode(byte[] input, int key)
        {
            StringBuilder outsb = new StringBuilder(input.Length);
            char ch;

            for (int i = 0; i < input.Length; i++)
            {
                ch = (char)(input[i] ^ key);
                outsb.Append(ch);
            }
            return outsb.ToString();
        }
    }
}
