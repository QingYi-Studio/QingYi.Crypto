using System.Text;
using System;

namespace QingYi.Crypto.XOR
{
    /// <summary>
    /// XOR crypto.<br></br>
    /// XOR加密。
    /// </summary>
    [Obsolete("For the best results, use the XorCryptoPlus class. This class will no longer be maintained and will not be updated later. It may be removed later.")]
    public class XorCrypto
    {
        /// <summary>
        /// Encodes a plain text string using a specified key with XOR encryption and returns the encoded string in Base64 format.<br></br>
        /// 使用带有异或加密的指定密钥对纯文本字符串进行编码，并以Base64格式返回编码后的字符串。
        /// </summary>
        /// <param name="plainText">The plain text string to be encoded.<br></br>要编码的纯文本字符串。</param>
        /// <param name="key">The key used for XOR encryption.<br></br>用于异或加密的密钥。</param>
        /// <returns>A Base64 encoded string representing the XOR encrypted plain text.|Base64编码的字符串，表示异或加密的纯文本。</returns>
        public static string EncodeString(string plainText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = Encoding.ASCII.GetBytes(plainText);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Convert.ToBase64String(cypherTextArray);
        }

        /// <summary>
        /// Decodes a Base64 encoded XOR encrypted string back to its original plain text using the specified key.<br></br>
        /// 使用指定的密钥将Base64编码的XOR加密字符串解码回其原始纯文本。
        /// </summary>
        /// <param name="cypherText">The Base64 encoded XOR encrypted string to be decoded.<br></br>要解码的Base64编码的异或加密字符串。</param>
        /// <param name="key">The key used for XOR decryption.<br></br>用于异或解密的密钥。</param>
        /// <returns>The original plain text string after decoding.|解码后的原始纯文本字符串。</returns>
        public static string DecodeString(string cypherText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = Convert.FromBase64String(cypherText);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Encoding.UTF8.GetString(plainTextArray);
        }

        /// <summary>
        /// Encodes a plain text string to a byte array using XOR encryption with the specified key.<br></br>
        /// 使用使用指定密钥的异或加密将纯文本字符串编码为字节数组。
        /// </summary>
        /// <param name="plainText">The plain text string to be encoded.<br></br>要编码的纯文本字符串。</param>
        /// <param name="key">The key used for XOR encryption.<br></br>用于异或加密的密钥。</param>
        /// <returns>A byte array representing the XOR encrypted plain text.|表示异或加密纯文本的字节数组。</returns>
        public static byte[] EncodeStringToBytes(string plainText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = Encoding.ASCII.GetBytes(plainText);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return cypherTextArray;
        }

        /// <summary>
        /// Decodes a Base64 encoded XOR encrypted byte array back to its original plain text using the specified key.<br></br>
        /// 使用指定的密钥将Base64编码的XOR加密字节数组解码回其原始纯文本。
        /// </summary>
        /// <param name="cypherText">The Base64 encoded XOR encrypted string to be decoded.<br></br>要解码的Base64编码的异或加密字符串。</param>
        /// <param name="key">The key used for XOR decryption.<br></br>用于异或解密的密钥。</param>
        /// <returns>A byte array representing the original plain text.|表示原始纯文本的字节数组。</returns>
        public static byte[] DecodeStringToBytes(string cypherText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = Convert.FromBase64String(cypherText);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return plainTextArray;
        }

        /// <summary>
        /// Encodes a byte array to a Base64 string using XOR encryption with the specified key.<br></br>
        /// 使用使用指定密钥的异或加密将字节数组编码为Base64字符串。
        /// </summary>
        /// <param name="plainTextArray">The byte array to be encoded.<br></br>要编码的字节数组。</param>
        /// <param name="key">The key used for XOR encryption.<br></br>用于异或加密的密钥。</param>
        /// <returns>A Base64 encoded string representing the XOR encrypted byte array.|表示异或加密字节数组的Base64编码字符串。</returns>
        public static string EncodeBytesToString(byte[] plainTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Convert.ToBase64String(cypherTextArray);
        }

        /// <summary>
        /// Decodes a Base64 encoded XOR encrypted string back to a byte array using the specified key.<br></br>
        /// 使用指定的密钥将Base64编码的XOR加密字符串解码回字节数组。
        /// </summary>
        /// <param name="cypherTextArray">The Base64 encoded XOR encrypted byte array to be decoded.<br></br>要解码的Base64编码的异或加密字节数组。</param>
        /// <param name="key">The key used for XOR decryption.<br></br>用于异或解密的密钥。</param>
        /// <returns>A byte array representing the original plain text.|表示原始纯文本的字节数组。</returns>
        public static string DecodeBytesToString(byte[] cypherTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Encoding.UTF8.GetString(plainTextArray);
        }

        /// <summary>
        /// Encodes a byte array using XOR encryption with the specified key.<br></br>
        /// 使用指定密钥使用异或加密对字节数组进行编码。
        /// </summary>
        /// <param name="plainTextArray">The byte array to be encoded.<br></br>要编码的字节数组。</param>
        /// <param name="key">The key used for XOR encryption.<br></br>用于异或加密的密钥。</param>
        /// <returns>A byte array representing the XOR encrypted byte array.|表示异或加密字节数组的字节数组。</returns>
        public static byte[] EncodeBytes(byte[] plainTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return cypherTextArray;
        }

        /// <summary>
        /// Decodes an XOR encrypted byte array back to its original form using the specified key.<br></br>
        /// 使用指定的密钥将XOR加密的字节数组解码回其原始形式。
        /// </summary>
        /// <param name="cypherTextArray">The XOR encrypted byte array to be decoded.<br></br>要解码的异或加密字节数组。</param>
        /// <param name="key">The key used for XOR decryption.<br></br>用于异或解密的密钥。</param>
        /// <returns>A byte array representing the original plain text.|表示原始纯文本的字节数组。</returns>
        public static byte[] DecodeBytes(byte[] cypherTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return plainTextArray;
        }
    }
}
