using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShellCodeCrypter
{
    internal class BlowMe
    {
        uint[] PArray;
        uint[] SBoxes;
        public BlowMe()
        {
            PArray = new uint[18];
            SBoxes = new uint[4 * 256];
            Initialize(Constants.NOT_SECRET_KEY);
        }

        void Initialize(byte[] key)
        {
            // Double the key to be able to take slices of 4 at all times
            var doubleKey = new byte[key.Length * 2];
            Array.Copy(key, 0, doubleKey, 0, key.Length);
            Array.Copy(key, 0, doubleKey, key.Length, key.Length);

            Constants.bf_P.CopyTo(PArray, 0);
            Constants.bf_S.CopyTo(SBoxes, 0);

            for (int i = 0, j = 0; i < Constants.NPASS + 2; ++i, j += 4)
            {
                uint temp = UIntFromBytes(doubleKey, j % key.Length, false);
                PArray[i] ^= temp;
            }

            Tuple<uint, uint> xlxr = Tuple.Create(0u, 0u);

            for (int i = 0; i < Constants.NPASS + 2; i += 2)
            {
                xlxr = Encipher(xlxr);
                PArray[i] = xlxr.Item1;
                PArray[i + 1] = xlxr.Item2;
            }

            for (int i = 0; i < 4; ++i)
            {
                for (int j = 0; j < 256; j += 2)
                {
                    xlxr = Encipher(xlxr);
                    SBoxes[i * 256 + j] = xlxr.Item1;
                    SBoxes[i * 256 + j + 1] = xlxr.Item2;
                }
            }
        }

        uint Round(uint b, int n)
        {
            //#define S(x,i) (SBoxes[i][x.w.byte##i])
            //#define bf_F(x) (((S(x,0) + S(x,1)) ^ S(x,2)) + S(x,3))
            //#define ROUND(a,b,n) (a.dword ^= bf_F(b) ^ PArray[n])

            var sbytes = BytesFromUInt(b, false);
            uint S0 = SBoxes[0 * 256 + sbytes[0]];
            uint S1 = SBoxes[1 * 256 + sbytes[1]];
            uint S2 = SBoxes[2 * 256 + sbytes[2]];
            uint S3 = SBoxes[3 * 256 + sbytes[3]];
            uint bf_F = ((S0 + S1) ^ S2) + S3;
            return bf_F ^ PArray[n];
        }

        Tuple<uint, uint> Encipher(Tuple<uint, uint> xlxr)
        {
            uint xl = xlxr.Item1;
            uint xr = xlxr.Item2;

            xl ^= PArray[0];
            for (int i = 1; i < 17; i += 2)
            {
                xr ^= Round(xl, i);
                xl ^= Round(xr, i + 1);
            }
            xr ^= PArray[17];

            return Tuple.Create(xr, xl);
        }

        uint GetOutputLength(uint len)
        {
            uint lval = len % 8;
            if (lval != 0)
            {
                return len + 8 - lval;
            }
            else
            {
                return len;
            }
        }

        private byte[] Encode(byte[] input)
        {
            if (input.Length % 8 != 0)
            {
                throw new ArgumentException("Input is not a multiple of 8 bytes");
            }

            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i += 8)
            {
                uint xl = UIntFromBytes(input, i, true);
                uint xr = UIntFromBytes(input, i + 4, true);

                Tuple<uint, uint> xlxr = Tuple.Create(xl, xr);
                xlxr = Encipher(xlxr);
                xl = xlxr.Item1;
                xr = xlxr.Item2;

                var outputl = BytesFromUInt(xl, true);
                var outputr = BytesFromUInt(xr, true);
                for (int j = 0; j < 4; ++j)
                {
                    output[i + j] = outputl[j];
                    output[i + j + 4] = outputr[j];
                }
            }

            return output;
        }


        static uint UIntFromBytes(byte[] input, int offset, bool littleEndian)
        {
            var output = new byte[4];
            Array.Copy(input, offset, output, 0, 4);

            if (BitConverter.IsLittleEndian != littleEndian)
            {
                Array.Reverse(output);
            }

            return BitConverter.ToUInt32(output, 0);
        }

        static byte[] BytesFromUInt(uint input, bool littleEndian)
        {
            var bytes = BitConverter.GetBytes(input);

            if (BitConverter.IsLittleEndian != littleEndian)
            {
                Array.Reverse(bytes);
            }

            return bytes;
        }


        public byte[] EncodeShell(byte[] payload)
        {
            var outlen = GetOutputLength((uint)payload.Length);
            var cipher_input = new byte[outlen];
            for (int i = 0; i < outlen; ++i)
            {
                if (i < payload.Length)
                {
                    cipher_input[i] = payload[i];
                }
                else
                {
                    cipher_input[i] = 0;
                }
            }

            var cipher_output = Encode(cipher_input);
            return cipher_output;
        }

    }
}
