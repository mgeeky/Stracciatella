using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

        public static string XorDecode(string input, int key)
        {
            StringBuilder insb = new StringBuilder(input);
            StringBuilder outsb = new StringBuilder(input.Length);
            char ch;

            for (int i = 0; i < input.Length; i++)
            {
                ch = insb[i];
                ch = (char)(ch ^ key);
                outsb.Append(ch);
            }
            return outsb.ToString();
        }
    }
}
