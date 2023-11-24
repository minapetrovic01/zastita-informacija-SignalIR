using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace Chat3
{
    public class PlayfairCipher
    {
        static bool flag = false;
        static char[,] GenerateKeyTable(string key)
        {
            char[,] keyTable = new char[5, 5];
            int[] dicty = new int[26];
            int k = 0;

            key = key.ToLower().Replace(" ", "");

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] != 'j')
                    dicty[key[i] - 'a'] = 2;
            }

            dicty['j' - 'a'] = 1;

            int row = 0, col = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (dicty[key[i] - 'a'] == 2)
                {
                    dicty[key[i] - 'a'] -= 1;
                    keyTable[row, col] = key[i];
                    col = (col + 1) % 5;
                    if (col == 0)
                        row++;
                }
            }

            for (int i = 0; i < 26; i++)
            {
                if (dicty[i] == 0)
                {
                    keyTable[row, col] = (char)(i + 'a');
                    col = (col + 1) % 5;
                    if (col == 0)
                        row++;
                }
            }

            return keyTable;
        }

        static void Search(char[,] keyTable, char a, char b, int[] arr)
        {
            int i, j;

            if (a == 'j')
                a = 'i';
            else if (b == 'j')
                b = 'i';

            for (i = 0; i < 5; i++)
            {
                for (j = 0; j < 5; j++)
                {
                    if (keyTable[i, j] == a)
                    {
                        arr[0] = i;
                        arr[1] = j;
                    }
                    else if (keyTable[i, j] == b)
                    {
                        arr[2] = i;
                        arr[3] = j;
                    }
                }
            }
        }

        static int Mod5(int a)
        {
            return (a % 5);
        }

        static string Prepare(string str, int ptrs)
        {
            string modifiedString = str.ToLower().Replace(" ", "");

            if (modifiedString.Length % 2 != 0)
            {
                modifiedString+=("z");
                flag = true;
            }
            return modifiedString;
        }

        static string Encrypt(string str, char[,] keyTable, int ps)
        {
            int[] a = new int[4];
            char[] array = str.ToCharArray();

            for (int i = 0; i < ps; i += 2)
            {
                Search(keyTable, array[i], array[i + 1], a);

                if (a[0] == a[2])
                {
                    array[i] = keyTable[a[0], Mod5(a[1] + 1)];
                    array[i + 1] = keyTable[a[0], Mod5(a[3] + 1)];
                }
                else if (a[1] == a[3])
                {
                    array[i] = keyTable[Mod5(a[0] + 1), a[1]];
                    array[i + 1] = keyTable[Mod5(a[2] + 1), a[1]];
                }
                else
                {
                    array[i] = keyTable[a[0], a[3]];
                    array[i + 1] = keyTable[a[2], a[1]];
                }
            }
            flag = false;
            return new string(array, 0, ps);
            
        }

        static string Decrypt(string str, char[,] keyTable, int ps)
        {
            int[] a = new int[4];
            char[] array = str.ToCharArray();

            for (int i = 0; i < ps; i += 2)
            {
                Search(keyTable, array[i], array[i + 1], a);

                if (a[0] == a[2])
                {
                    array[i] = keyTable[a[0], Mod5(a[1] - 1)];
                    array[i + 1] = keyTable[a[0], Mod5(a[3] - 1)];
                }
                else if (a[1] == a[3])
                {
                    array[i] = keyTable[Mod5(a[0] - 1), a[1]];
                    array[i + 1] = keyTable[Mod5(a[2] - 1), a[1]];
                }
                else
                {
                    array[i] = keyTable[a[0], a[3]];
                    array[i + 1] = keyTable[a[2], a[1]];
                }
            }
            return new string(array, 0, ps);
        }

        public static string EncryptByPlayfairCipher(string str, string key)
        {
            char[,] keyTable = GenerateKeyTable(key);

            string modified=Prepare(str, str.Length);
            string output=Encrypt(modified, keyTable, modified.Length);
            return output;
        }

        public static string DecryptByPlayfairCipher(string str, string key)
        {
            char[,] keyTable = GenerateKeyTable(key);

            string modified = Prepare(str, str.Length);
            string output=Decrypt(modified, keyTable, modified.Length);
            return output;

        }
    }
}
