using System;
using System.Text;

namespace QingYi.Crypto.XOR
{
    /// <summary>
    /// Xor crypto plus.<br></br>
    /// 异或加密增强版。
    /// </summary>
    public class XorCryptoPlus
    {
        /// <summary>
        /// Encrypt or decrypt the byte array using the XOR algorithm<br />
        /// 使用XOR算法加密或解密字节数组
        /// </summary>
        /// <param name="input">Input byte array<br />输入字节数组</param>
        /// <param name="key">Encryption key<br />加密密钥</param>
        /// <returns>The processed byte array<br />处理后的字节数组</returns>
        public static byte[] Xor(byte[] input, byte[] key)
        {
            if (input == null || input.Length == 0)
                return Array.Empty<byte>();

            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty");

            byte[] output = new byte[input.Length];

            unsafe
            {
                fixed (byte* pInput = input, pOutput = output, pKey = key)
                {
                    for (int i = 0; i < input.Length; i++)
                    {
                        pOutput[i] = (byte)(pInput[i] ^ pKey[i % key.Length]);
                    }
                }
            }

            return output;
        }

        /// <summary>
        /// Encrypt or decrypt the byte array using the XOR algorithm<br />
        /// 使用XOR算法加密或解密字节数组
        /// </summary>
        /// <param name="input">Input byte array<br />输入字节数组</param>
        /// <param name="key">Encryption key<br />加密密钥</param>
        /// <returns>The processed byte array<br />处理后的字节数组</returns>
        public static byte[] Xor(byte[] input, string key)
        {
            if (input == null || input.Length == 0)
                return Array.Empty<byte>();

            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            return Xor(input, keyBytes);
        }

        /// <summary>
        /// Encrypt or decrypt strings using the XOR algorithm<br />
        /// 使用XOR算法加密或解密字符串
        /// </summary>
        /// <param name="input">Input string<br />输入字符串</param>
        /// <param name="key">Encryption key<br />加密密钥</param>
        /// <returns>The processed string<br />处理后的字符串</returns>
        public static string Xor(string input, byte[] key)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            byte[] bytes = Encoding.UTF8.GetBytes(input);
            byte[] processed = Xor(bytes, key);
            return Encoding.UTF8.GetString(processed);
        }

        /// <summary>
        /// Encrypt or decrypt strings using the XOR algorithm<br />
        /// 使用XOR算法加密或解密字符串
        /// </summary>
        /// <param name="input">Input string<br />输入字符串</param>
        /// <param name="key">Encryption key<br />加密密钥</param>
        /// <returns>The processed string<br />处理后的字符串</returns>
        public static string Xor(string input, string key)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            byte[] bytes = Encoding.UTF8.GetBytes(input);
            byte[] processed = Xor(bytes, key);
            return Encoding.UTF8.GetString(processed);
        }

        /// <summary>
        /// Encrypt or decrypt string arrays using the XOR algorithm<br />
        /// 使用XOR算法加密或解密字符串数组
        /// </summary>
        /// <param name="input">Input an array of strings<br />输入字符串数组</param>
        /// <param name="key">Encryption key<br />加密密钥</param>
        /// <returns>The processed string array<br />处理后的字符串数组</returns>
        public static string[] Xor(string[] input, byte[] key)
        {
            if (input == null || input.Length == 0)
                return Array.Empty<string>();

            string[] output = new string[input.Length];

            for (int i = 0; i < input.Length; i++)
            {
                output[i] = Xor(input[i], key);
            }

            return output;
        }

        /// <summary>
        /// Encrypt or decrypt string arrays using the XOR algorithm<br />
        /// 使用XOR算法加密或解密字符串数组
        /// </summary>
        /// <param name="input">Input an array of strings<br />输入字符串数组</param>
        /// <param name="key">Encryption key<br />加密密钥</param>
        /// <returns>The processed string array<br />处理后的字符串数组</returns>
        public static string[] Xor(string[] input, string key)
        {
            if (input == null || input.Length == 0)
                return Array.Empty<string>();

            string[] output = new string[input.Length];

            for (int i = 0; i < input.Length; i++)
            {
                output[i] = Xor(input[i], key);
            }

            return output;
        }

        /// <summary>
        /// Encrypt or decrypt the character array using the XOR algorithm<br />
        /// 使用XOR算法加密或解密字符数组
        /// </summary>
        /// <param name="input">Input character array<br />输入字符数组</param>
        /// <param name="key">Encryption key<br />加密密钥</param>
        /// <returns>The processed character array<br />处理后的字符数组</returns>
        public static char[] Xor(char[] input, string key)
        {
            if (input == null || input.Length == 0)
                return Array.Empty<char>();

            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            char[] output = new char[input.Length];

            unsafe
            {
                fixed (char* pInput = input, pOutput = output)
                {
                    fixed (char* pKey = key)
                    {
                        for (int i = 0; i < input.Length; i++)
                        {
                            pOutput[i] = (char)(pInput[i] ^ pKey[i % key.Length]);
                        }
                    }
                }
            }

            return output;
        }
    }
}
