using System.Security.Cryptography;
using System.Text;

namespace Chat3
{
    public class RC6PCBC
    {
        private static int rounds;
        private static int blockSize;
        public static void SetRounds(string r)
        {
            try
            {
                rounds = int.Parse(r);
            }
            catch
            {
                throw new ArgumentException(r + " is not a valid number of rounds");
            }
        }
        public static void SetBlockSize(string b)
        {
            try
            {
                blockSize = int.Parse(b);
            }
            catch
            {
                throw new ArgumentException(b + " is not a valid block size");
            }
        }
        static uint[] KeyExpansion(byte[] key)
        {
            int u = blockSize / 4;
            int c = key.Length / u;
            int t = 2 * (rounds + 1);
            uint[] expandedKey = new uint[t];
            uint[] L = new uint[c];

            uint P=0xB7E15163, Q=0x9E3779B9;

            for (int i = 0; i < c; i++)
            {
                L[i] = BitConverter.ToUInt32(key, i * u);
            }

            expandedKey[0] = P;
            for (int i = 1; i < t; i++)
            {
                expandedKey[i] = expandedKey[i - 1] + Q;
            }

            int A, B, ii, j;
            A = B = ii = j = 0;

            uint[] temp = new uint[t];
            Array.Copy(expandedKey, temp, t);

            for (int s = 0, max = 3 * Math.Max(c, t); s < max; s++)
            {
                uint shiftedA = RotateLeft(temp[ii] + (uint)A + (uint)B, 3);
                temp[ii] = shiftedA;
                A = (int)shiftedA;
                uint shiftedB = RotateLeft(L[j] + (uint)A + (uint)B, (int)(A + B));
                L[j] = shiftedB;
                B = (int)shiftedB;

                ii = (ii + 1) % t;
                j = (j + 1) % c;
            }

            return temp;
        }
        private static byte[] EncryptBlock(byte[] input, uint[] expandedKey)
        {
            uint A = BitConverter.ToUInt32(input, 0);
            uint B = BitConverter.ToUInt32(input, 4);
            uint C = BitConverter.ToUInt32(input, 8);
            uint D = BitConverter.ToUInt32(input, 12);

            B += expandedKey[0];
            D += expandedKey[1];

            for (int i = 1; i <= rounds; i++)
            {
                uint t = RotateLeft((B * (2 * B + 1)), 5);
                uint u = RotateLeft((D * (2 * D + 1)), 5);

                A = RotateLeft((A ^ t), (int)u) + expandedKey[2 * i];
                C = RotateLeft((C ^ u), (int)t) + expandedKey[2 * i + 1];

                uint temp = A;
                A = B;
                B = C;
                C = D;
                D = temp;
            }

            A += expandedKey[2 * rounds];
            C += expandedKey[2 * rounds + 1];

            byte[] output = new byte[blockSize];
            BitConverter.GetBytes(A).CopyTo(output, 0);
            BitConverter.GetBytes(B).CopyTo(output, 4);
            BitConverter.GetBytes(C).CopyTo(output, 8);
            BitConverter.GetBytes(D).CopyTo(output, 12);

            return output;
        }

        private static byte[] DecryptBlock(byte[] input, uint[] expandedKey)
        {
            uint A = BitConverter.ToUInt32(input, 0);
            uint B = BitConverter.ToUInt32(input, 4);
            uint C = BitConverter.ToUInt32(input, 8);
            uint D = BitConverter.ToUInt32(input, 12);

            C -= expandedKey[2 * rounds + 1];
            A -= expandedKey[2 * rounds];

            for (int i = rounds; i >= 1; i--)
            {
                uint temp = D;
                D = C;
                C = B;
                B = A;
                A = temp;

                uint t = RotateLeft((B * (2 * B + 1)), 5);
                uint u = RotateLeft((D * (2 * D + 1)), 5);

                C = RotateRight((C - expandedKey[2 * i + 1]), (int)t) ^ u;
                A = RotateRight((A - expandedKey[2 * i]), (int)u) ^ t;
            }

            D -= expandedKey[1];
            B -= expandedKey[0];

            byte[] output = new byte[blockSize];
            BitConverter.GetBytes(A).CopyTo(output, 0);
            BitConverter.GetBytes(B).CopyTo(output, 4);
            BitConverter.GetBytes(C).CopyTo(output, 8);
            BitConverter.GetBytes(D).CopyTo(output, 12);

            return output;
        }

        private static uint RotateLeft(uint value, int offset)
        {
            return (value << offset) | (value >> (32 - offset));
        }

        private static uint RotateRight(uint value, int offset)
        {
            return (value >> offset) | (value << (32 - offset));
        }

        public static string EncryptbyRC6(string plaintextStr, string keyStr, string ivStr)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyStr); 
            byte[] iv = Encoding.UTF8.GetBytes(ivStr);

            byte[] plaintext = Encoding.UTF8.GetBytes(plaintextStr);


            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new ArgumentException("Key must be 128, 192, or 256 bits long.");
            }

            if (iv.Length != blockSize)
            {
                throw new ArgumentException("Initialization Vector (IV) must be 16 bytes long.");
            }

            uint[] expandedKey = KeyExpansion(key);
            byte[] paddedPlaintext = AddPadding(plaintext);
            byte[] ciphertext = new byte[paddedPlaintext.Length];
            byte[] previousCipherBlock = iv;


            for (int i = 0; i < paddedPlaintext.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Buffer.BlockCopy(paddedPlaintext, i, block, 0, blockSize);

                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= previousCipherBlock[j];
                }
                if (i != 0)
                {
                    for (int j = 0; j < blockSize; j++)
                    {
                        block[j] ^= paddedPlaintext[i - blockSize + j];
                    }
                }

                byte[] encryptedBlock = EncryptBlock(block, expandedKey);

                Buffer.BlockCopy(encryptedBlock, 0, previousCipherBlock, 0, blockSize);
                Buffer.BlockCopy(encryptedBlock, 0, ciphertext, i, blockSize);
            }

            return Convert.ToBase64String(ciphertext);
        }


        public static string DecryptbyRC6(string ciphertextStr, string keyStr, string ivStr)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyStr);
            byte[] iv = Encoding.UTF8.GetBytes(ivStr);

            byte [] ciphertext= Convert.FromBase64String(ciphertextStr);

            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new ArgumentException("Key must be 128, 192, or 256 bits long.");
            }

            if (iv.Length != blockSize)
            {
                throw new ArgumentException("Initialization Vector (IV) must be 16 bytes long.");
            }

            uint[] expandedKey = KeyExpansion(key);
            byte[] plaintext = new byte[ciphertext.Length];

            byte[] previousCipherBlock = iv;

            for (int i = 0; i < ciphertext.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Buffer.BlockCopy(ciphertext, i, block, 0, blockSize);

                byte[] decryptedBlock = DecryptBlock(block, expandedKey);

                if (i != 0)
                {
                    for (int j = 0; j < blockSize; j++)
                    {
                        decryptedBlock[j] ^= decryptedBlock[i - blockSize + j];
                    }
                }

                for (int j = 0; j < blockSize; j++)
                {
                    decryptedBlock[j] ^= previousCipherBlock[j];
                }

                Buffer.BlockCopy(decryptedBlock, 0, plaintext, i, blockSize);
                Buffer.BlockCopy(block, 0, previousCipherBlock, 0, blockSize);
            }

            byte[] unpaddedPlaintext = RemovePadding(plaintext);

            return Encoding.UTF8.GetString(unpaddedPlaintext);
        }

        private static byte[] AddPadding(byte[] input)
        {
            int paddingLength = blockSize - (input.Length % blockSize);
            byte paddingByte = (byte)paddingLength;

            byte[] paddedInput = new byte[input.Length + paddingLength];
            Buffer.BlockCopy(input, 0, paddedInput, 0, input.Length);

            for (int i = input.Length; i < paddedInput.Length; i++)
            {
                paddedInput[i] = paddingByte;
            }

            return paddedInput;
        }


        private static byte[] RemovePadding(byte[] input)
        {
            if (input == null || input.Length == 0)
            {
                throw new CryptographicException("Invalid PKCS7 padding.");
            }

            int paddingLength = input[input.Length - 1];

            if (paddingLength < 1 || paddingLength > blockSize || paddingLength > input.Length)
            {
                throw new CryptographicException("Invalid PKCS7 padding.");
            }

            for (int i = input.Length - paddingLength; i < input.Length; i++)
            {
                if (input[i] != paddingLength)
                {
                    throw new CryptographicException("Invalid PKCS7 padding.");
                }
            }

            byte[] unpaddedInput = new byte[input.Length - paddingLength];
            Buffer.BlockCopy(input, 0, unpaddedInput, 0, unpaddedInput.Length);

            return unpaddedInput;
        }
    }
}
    
