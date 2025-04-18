using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AES
{
    /// <summary>
    /// CBC encryption mode.<br></br>
    /// CBC加密模式。
    /// </summary>
    public class CBC
    {
        /// <summary>
        /// Converts a hexadecimal string to a byte array.<br></br>
        /// 将十六进制字符串转换为字节数组。
        /// </summary>
        /// <param name="hex">
        /// The hexadecimal string to convert.<br></br>
        /// 要转换的十六进制字符串。
        /// </param>
        /// <param name="expectedLength">
        /// The desired byte length.<br></br>
        /// 所需的字节长度。
        /// </param>
        /// <returns>
        /// The corresponding byte array.<br></br>
        /// 对应的字节数组。
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the length of the <paramref name="hex"/> string is not an even number.<br></br>
        /// 当<paramref name="hex"/>字符串的长度不是偶数时抛出。
        /// </exception>
        private static byte[] FormattingKeyIV(string hex, int expectedLength)
        {
            if (string.IsNullOrWhiteSpace(hex))
            {
                throw new ArgumentException("Hex string cannot be null or empty.", nameof(hex));
            }

            hex = Regex.Replace(hex, @"[^0-9A-Fa-f]", string.Empty);

            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hex string must have an even length.", nameof(hex));
            }

            if (hex.Length > expectedLength * 2)
            {
                hex = hex.Substring(0, expectedLength * 2);
            }
            else if (hex.Length < expectedLength * 2)
            {
                hex = hex.PadLeft(expectedLength * 2, '0');
            }

            byte[] bytes = new byte[expectedLength];

            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

        /// <summary>
        /// PKCS7 padding mode.
        /// PKCS7 填充模式。
        /// </summary>
        public class PKCS7
        {
            /// <summary>
            /// Encrypts the given plain text using AES encryption with the specified key and initialization vector (IV).<br></br>
            /// 使用带有指定密钥和初始化向量(IV)的AES加密对给定的明文进行加密。
            /// </summary>
            /// <param name="plainText">
            /// The plain text to encrypt.<br></br>
            /// 要加密的纯文本。
            /// </param>
            /// <param name="keyHex">
            /// The AES encryption key in hexadecimal format. Must be 64 hex characters long (32 bytes).<br></br>
            /// 十六进制AES加密密钥。必须是64个十六进制字符长(32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The initialization vector (IV) in hexadecimal format. Must be 32 hex characters long (16 bytes).<br></br>
            /// 十六进制格式的初始化向量(IV)。必须是32个十六进制字符长(16字节)。
            /// </param>
            /// <returns>
            /// The encrypted text encoded in Base64 format.<br></br>
            /// 以Base64格式编码的加密文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> is null.<br></br>
            /// 当<paramref name="plainText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> are invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出
            /// </exception>
            public static string EncryptString(string plainText, string keyHex, string ivHex)
            {
                if (plainText == null) throw new ArgumentNullException(nameof(plainText));

                // 将十六进制格式的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32); // 32 字节密钥对应 AES-256
                byte[] iv = FormattingKeyIV(ivHex, 16);   // 16 字节 IV 对应 AES

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        // 写入明文数据并确保所有数据都被写入
                        sw.Write(plainText);
                        sw.Flush(); // 确保所有数据被写入到 CryptoStream
                        cs.FlushFinalBlock(); // 确保完成加密操作
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded cipher text using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV解密base64编码的密文。
            /// </summary>
            /// <param name="cipherText">
            /// The base64-encoded encrypted text.<br></br>
            /// base64编码的加密文本。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示形式(64个十六进制字符，32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示(32个十六进制字符表示16字节)。
            /// </param>
            /// <returns>
            /// The decrypted plain text.<br></br>
            /// 解密后的纯文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherText"/> is null.<br></br>
            /// 当<paramref name="cipherText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出。
            /// </exception>
            public static string DecryptString(string cipherText, string keyHex, string ivHex)
            {
                // 检查加密文本是否为空
                if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));

                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                // 创建Aes对象来执行解密
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建解密器
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 使用MemoryStream和CryptoStream来解密数据
                    using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader sr = new StreamReader(cs))
                            {
                                // 读取并返回解密后的明文
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts byte array data to a base64-encoded string using a specified key and IV.<br></br>
            /// 将字节数组数据加密为使用指定密钥和IV的Base64编码字符串。
            /// </summary>
            /// <param name="data">
            /// The byte array data to be encrypted.<br></br>
            /// 要加密的字节数组数据。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The base64-encoded encrypted string.<br></br>
            /// Base64编码的加密字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string EncryptBytesToString(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(data, 0, data.Length); // 写入数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return Convert.ToBase64String(ms.ToArray()); // 返回Base64编码的加密字符串
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded encrypted string back to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将Base64编码的加密字符串解密回字节数组。
            /// </summary>
            /// <param name="encryptedData">
            /// The base64-encoded encrypted string to be decrypted.<br></br>
            /// 要解密的Base64编码的加密字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptStringToBytes(string encryptedData, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData); // 从Base64字符串转换为字节数组

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(encryptedBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                using (MemoryStream result = new MemoryStream())
                                {
                                    cs.CopyTo(result); // 复制解密后的数据到结果流
                                    return result.ToArray(); // 返回解密后的字节数组
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">
            /// The plain text string to be encrypted.<br></br>
            /// 要加密的纯文本字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="plainText"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        // 将明文字符串转换为字节数组
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(plainBytes, 0, plainBytes.Length); // 写入明文字节数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return ms.ToArray(); // 返回加密后的字节数组
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array back to a plain text string using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted plain text string.<br></br>
            /// 解密后的纯文本字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherBytes"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="cipherBytes"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(cipherBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                // 使用StreamReader读取解密后的数据
                                using (StreamReader reader = new StreamReader(cs))
                                {
                                    return reader.ReadToEnd(); // 返回解密后的明文字符串
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption and writes the encrypted data to a new file.<br></br>
            /// 使用AES加密对文件进行加密，并将加密数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                    {
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption and writes the decrypted data to a new file.<br></br>
            /// 使用AES解密对文件进行解密，并将解密后的数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be decrypted.<br></br>
            /// 要解密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                    {
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted data as a byte array.<br></br>
            /// 使用AES加密对字节数组进行加密，并返回加密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption and returns the decrypted data as a byte array.<br></br>
            /// 使用AES解密对字节数组进行解密，并返回解密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be decrypted.<br></br>
            /// 要解密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行解密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被解密
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.<br></br>
            /// 加密文件并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件的路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] EncryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将文件内容复制到CryptoStream中进行加密
                            fs.CopyTo(cs);
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br></br>
            /// 解密字节数组并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedData">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据的字节数组。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptBytesToFile(byte[] encryptedData, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        // 将解密后的数据从CryptoStream复制到文件中
                        cs.CopyTo(fs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br></br>
            /// 加密字节数组并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="filePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptBytesToFile(byte[] data, string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行加密
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密，并最终写入文件
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts data from a file and returns the decrypted data as a byte array.<br></br>
            /// 从文件中解密数据并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the file containing the encrypted data.<br></br>
            /// 包含加密数据的文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] DecryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行解密
                    aes.Padding = PaddingMode.PKCS7; // 使用PKCS7填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            // 从文件中读取加密数据并解密
                            cs.CopyTo(ms);
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }
        }

        /// <summary>
        /// None padding mode.
        /// None 填充模式。
        /// </summary>
        public class None
        {
            /// <summary>
            /// Encrypts the given plain text using AES encryption with the specified key and initialization vector (IV).<br></br>
            /// 使用带有指定密钥和初始化向量(IV)的AES加密对给定的明文进行加密。
            /// </summary>
            /// <param name="plainText">
            /// The plain text to encrypt.<br></br>
            /// 要加密的纯文本。
            /// </param>
            /// <param name="keyHex">
            /// The AES encryption key in hexadecimal format. Must be 64 hex characters long (32 bytes).<br></br>
            /// 十六进制AES加密密钥。必须是64个十六进制字符长(32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The initialization vector (IV) in hexadecimal format. Must be 32 hex characters long (16 bytes).<br></br>
            /// 十六进制格式的初始化向量(IV)。必须是32个十六进制字符长(16字节)。
            /// </param>
            /// <returns>
            /// The encrypted text encoded in Base64 format.<br></br>
            /// 以Base64格式编码的加密文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> is null.<br></br>
            /// 当<paramref name="plainText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> are invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出
            /// </exception>
            public static string EncryptString(string plainText, string keyHex, string ivHex)
            {
                // 检查明文是否为null
                if (plainText == null) throw new ArgumentNullException(nameof(plainText));

                // 将十六进制格式的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    // 设置AES加密算法的密钥和初始化向量
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建加密转换器
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        // 创建CryptoStream以将数据写入内存流
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 使用StreamWriter写入明文数据
                            using (StreamWriter sw = new StreamWriter(cs))
                            {
                                sw.Write(plainText);
                            }
                        }
                        // 将加密后的数据转换为Base64字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded cipher text using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV解密base64编码的密文。
            /// </summary>
            /// <param name="cipherText">
            /// The base64-encoded encrypted text.<br></br>
            /// base64编码的加密文本。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示形式(64个十六进制字符，32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示(32个十六进制字符表示16字节)。
            /// </param>
            /// <returns>
            /// The decrypted plain text.<br></br>
            /// 解密后的纯文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherText"/> is null.<br></br>
            /// 当<paramref name="cipherText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出。
            /// </exception>
            public static string DecryptString(string cipherText, string keyHex, string ivHex)
            {
                // 检查加密文本是否为空
                if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));

                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                // 创建Aes对象来执行解密
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建解密器
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 使用MemoryStream和CryptoStream来解密数据
                    using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader sr = new StreamReader(cs))
                            {
                                // 读取并返回解密后的明文
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts byte array data to a base64-encoded string using a specified key and IV.<br></br>
            /// 将字节数组数据加密为使用指定密钥和IV的Base64编码字符串。
            /// </summary>
            /// <param name="data">
            /// The byte array data to be encrypted.<br></br>
            /// 要加密的字节数组数据。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The base64-encoded encrypted string.<br></br>
            /// Base64编码的加密字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string EncryptBytesToString(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(data, 0, data.Length); // 写入数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return Convert.ToBase64String(ms.ToArray()); // 返回Base64编码的加密字符串
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded encrypted string back to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将Base64编码的加密字符串解密回字节数组。
            /// </summary>
            /// <param name="encryptedData">
            /// The base64-encoded encrypted string to be decrypted.<br></br>
            /// 要解密的Base64编码的加密字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptStringToBytes(string encryptedData, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData); // 从Base64字符串转换为字节数组

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(encryptedBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                using (MemoryStream result = new MemoryStream())
                                {
                                    cs.CopyTo(result); // 复制解密后的数据到结果流
                                    return result.ToArray(); // 返回解密后的字节数组
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">
            /// The plain text string to be encrypted.<br></br>
            /// 要加密的纯文本字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="plainText"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        // 将明文字符串转换为字节数组
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(plainBytes, 0, plainBytes.Length); // 写入明文字节数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return ms.ToArray(); // 返回加密后的字节数组
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array back to a plain text string using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted plain text string.<br></br>
            /// 解密后的纯文本字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherBytes"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="cipherBytes"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(cipherBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                // 使用StreamReader读取解密后的数据
                                using (StreamReader reader = new StreamReader(cs))
                                {
                                    return reader.ReadToEnd(); // 返回解密后的明文字符串
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption and writes the encrypted data to a new file.<br></br>
            /// 使用AES加密对文件进行加密，并将加密数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行加密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption and writes the decrypted data to a new file.<br></br>
            /// 使用AES解密对文件进行解密，并将解密后的数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be decrypted.<br></br>
            /// 要解密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行解密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted data as a byte array.<br></br>
            /// 使用AES加密对字节数组进行加密，并返回加密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption and returns the decrypted data as a byte array.<br></br>
            /// 使用AES解密对字节数组进行解密，并返回解密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be decrypted.<br></br>
            /// 要解密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行解密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被解密
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.<br></br>
            /// 加密文件并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件的路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] EncryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将文件内容复制到CryptoStream中进行加密
                            fs.CopyTo(cs);
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br></br>
            /// 解密字节数组并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedData">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据的字节数组。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptBytesToFile(byte[] encryptedData, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        // 将解密后的数据从CryptoStream复制到文件中
                        cs.CopyTo(fs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br></br>
            /// 加密字节数组并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="filePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptBytesToFile(byte[] data, string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行加密
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密，并最终写入文件
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts data from a file and returns the decrypted data as a byte array.<br></br>
            /// 从文件中解密数据并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the file containing the encrypted data.<br></br>
            /// 包含加密数据的文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] DecryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行解密
                    aes.Padding = PaddingMode.None; // 使用None填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            // 从文件中读取加密数据并解密
                            cs.CopyTo(ms);
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }
        }

        /// <summary>
        /// Zeros padding mode.
        /// Zeros 填充模式。
        /// </summary>
        public class Zeros
        {
            /// <summary>
            /// Encrypts the given plain text using AES encryption with the specified key and initialization vector (IV).<br></br>
            /// 使用带有指定密钥和初始化向量(IV)的AES加密对给定的明文进行加密。
            /// </summary>
            /// <param name="plainText">
            /// The plain text to encrypt.<br></br>
            /// 要加密的纯文本。
            /// </param>
            /// <param name="keyHex">
            /// The AES encryption key in hexadecimal format. Must be 64 hex characters long (32 bytes).<br></br>
            /// 十六进制AES加密密钥。必须是64个十六进制字符长(32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The initialization vector (IV) in hexadecimal format. Must be 32 hex characters long (16 bytes).<br></br>
            /// 十六进制格式的初始化向量(IV)。必须是32个十六进制字符长(16字节)。
            /// </param>
            /// <returns>
            /// The encrypted text encoded in Base64 format.<br></br>
            /// 以Base64格式编码的加密文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> is null.<br></br>
            /// 当<paramref name="plainText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> are invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出
            /// </exception>
            public static string EncryptString(string plainText, string keyHex, string ivHex)
            {
                // 检查明文是否为null
                if (plainText == null) throw new ArgumentNullException(nameof(plainText));

                // 检查密钥是否为有效的64个十六进制字符（即32字节）
                if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
                    throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));

                // 检查初始化向量（IV）是否为有效的32个十六进制字符（即16字节）
                if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32)
                    throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

                // 将十六进制格式的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    // 设置AES加密算法的密钥和初始化向量
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建加密转换器
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        // 创建CryptoStream以将数据写入内存流
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 使用StreamWriter写入明文数据
                            using (StreamWriter sw = new StreamWriter(cs))
                            {
                                sw.Write(plainText);
                            }
                        }
                        // 将加密后的数据转换为Base64字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded cipher text using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV解密base64编码的密文。
            /// </summary>
            /// <param name="cipherText">
            /// The base64-encoded encrypted text.<br></br>
            /// base64编码的加密文本。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示形式(64个十六进制字符，32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示(32个十六进制字符表示16字节)。
            /// </param>
            /// <returns>
            /// The decrypted plain text.<br></br>
            /// 解密后的纯文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherText"/> is null.<br></br>
            /// 当<paramref name="cipherText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出。
            /// </exception>
            public static string DecryptString(string cipherText, string keyHex, string ivHex)
            {
                // 检查加密文本是否为空
                if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));

                // 验证密钥的长度是否为64个十六进制字符，即32字节
                if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
                    throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));

                // 验证IV的长度是否为32个十六进制字符，即16字节
                if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32)
                    throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                // 创建Aes对象来执行解密
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建解密器
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 使用MemoryStream和CryptoStream来解密数据
                    using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader sr = new StreamReader(cs))
                            {
                                // 读取并返回解密后的明文
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts byte array data to a base64-encoded string using a specified key and IV.<br></br>
            /// 将字节数组数据加密为使用指定密钥和IV的Base64编码字符串。
            /// </summary>
            /// <param name="data">
            /// The byte array data to be encrypted.<br></br>
            /// 要加密的字节数组数据。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The base64-encoded encrypted string.<br></br>
            /// Base64编码的加密字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string EncryptBytesToString(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(data, 0, data.Length); // 写入数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return Convert.ToBase64String(ms.ToArray()); // 返回Base64编码的加密字符串
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded encrypted string back to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将Base64编码的加密字符串解密回字节数组。
            /// </summary>
            /// <param name="encryptedData">
            /// The base64-encoded encrypted string to be decrypted.<br></br>
            /// 要解密的Base64编码的加密字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptStringToBytes(string encryptedData, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData); // 从Base64字符串转换为字节数组

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(encryptedBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                using (MemoryStream result = new MemoryStream())
                                {
                                    cs.CopyTo(result); // 复制解密后的数据到结果流
                                    return result.ToArray(); // 返回解密后的字节数组
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">
            /// The plain text string to be encrypted.<br></br>
            /// 要加密的纯文本字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="plainText"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        // 将明文字符串转换为字节数组
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(plainBytes, 0, plainBytes.Length); // 写入明文字节数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return ms.ToArray(); // 返回加密后的字节数组
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array back to a plain text string using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted plain text string.<br></br>
            /// 解密后的纯文本字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherBytes"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="cipherBytes"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(cipherBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                // 使用StreamReader读取解密后的数据
                                using (StreamReader reader = new StreamReader(cs))
                                {
                                    return reader.ReadToEnd(); // 返回解密后的明文字符串
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption and writes the encrypted data to a new file.<br></br>
            /// 使用AES加密对文件进行加密，并将加密数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行加密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption and writes the decrypted data to a new file.<br></br>
            /// 使用AES解密对文件进行解密，并将解密后的数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be decrypted.<br></br>
            /// 要解密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行解密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted data as a byte array.<br></br>
            /// 使用AES加密对字节数组进行加密，并返回加密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption and returns the decrypted data as a byte array.<br></br>
            /// 使用AES解密对字节数组进行解密，并返回解密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be decrypted.<br></br>
            /// 要解密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行解密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被解密
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.<br></br>
            /// 加密文件并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件的路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] EncryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将文件内容复制到CryptoStream中进行加密
                            fs.CopyTo(cs);
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br></br>
            /// 解密字节数组并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedData">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据的字节数组。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptBytesToFile(byte[] encryptedData, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        // 将解密后的数据从CryptoStream复制到文件中
                        cs.CopyTo(fs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br></br>
            /// 加密字节数组并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="filePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptBytesToFile(byte[] data, string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行加密
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密，并最终写入文件
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts data from a file and returns the decrypted data as a byte array.<br></br>
            /// 从文件中解密数据并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the file containing the encrypted data.<br></br>
            /// 包含加密数据的文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] DecryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行解密
                    aes.Padding = PaddingMode.Zeros; // 使用Zeros填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            // 从文件中读取加密数据并解密
                            cs.CopyTo(ms);
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }
        }

        /// <summary>
        /// ISO10126 padding mode.
        /// ISO10126 填充模式。
        /// </summary>
        public class ISO10126
        {
            /// <summary>
            /// Encrypts the given plain text using AES encryption with the specified key and initialization vector (IV).<br></br>
            /// 使用带有指定密钥和初始化向量(IV)的AES加密对给定的明文进行加密。
            /// </summary>
            /// <param name="plainText">
            /// The plain text to encrypt.<br></br>
            /// 要加密的纯文本。
            /// </param>
            /// <param name="keyHex">
            /// The AES encryption key in hexadecimal format. Must be 64 hex characters long (32 bytes).<br></br>
            /// 十六进制AES加密密钥。必须是64个十六进制字符长(32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The initialization vector (IV) in hexadecimal format. Must be 32 hex characters long (16 bytes).<br></br>
            /// 十六进制格式的初始化向量(IV)。必须是32个十六进制字符长(16字节)。
            /// </param>
            /// <returns>
            /// The encrypted text encoded in Base64 format.<br></br>
            /// 以Base64格式编码的加密文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> is null.<br></br>
            /// 当<paramref name="plainText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> are invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出
            /// </exception>
            public static string EncryptString(string plainText, string keyHex, string ivHex)
            {
                // 检查明文是否为null
                if (plainText == null) throw new ArgumentNullException(nameof(plainText));

                // 检查密钥是否为有效的64个十六进制字符（即32字节）
                if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
                    throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));

                // 检查初始化向量（IV）是否为有效的32个十六进制字符（即16字节）
                if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32)
                    throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

                // 将十六进制格式的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    // 设置AES加密算法的密钥和初始化向量
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建加密转换器
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        // 创建CryptoStream以将数据写入内存流
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 使用StreamWriter写入明文数据
                            using (StreamWriter sw = new StreamWriter(cs))
                            {
                                sw.Write(plainText);
                            }
                        }
                        // 将加密后的数据转换为Base64字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded cipher text using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV解密base64编码的密文。
            /// </summary>
            /// <param name="cipherText">
            /// The base64-encoded encrypted text.<br></br>
            /// base64编码的加密文本。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示形式(64个十六进制字符，32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示(32个十六进制字符表示16字节)。
            /// </param>
            /// <returns>
            /// The decrypted plain text.<br></br>
            /// 解密后的纯文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherText"/> is null.<br></br>
            /// 当<paramref name="cipherText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出。
            /// </exception>
            public static string DecryptString(string cipherText, string keyHex, string ivHex)
            {
                // 检查加密文本是否为空
                if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));

                // 验证密钥的长度是否为64个十六进制字符，即32字节
                if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
                    throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));

                // 验证IV的长度是否为32个十六进制字符，即16字节
                if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32)
                    throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                // 创建Aes对象来执行解密
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建解密器
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 使用MemoryStream和CryptoStream来解密数据
                    using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader sr = new StreamReader(cs))
                            {
                                // 读取并返回解密后的明文
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts byte array data to a base64-encoded string using a specified key and IV.<br></br>
            /// 将字节数组数据加密为使用指定密钥和IV的Base64编码字符串。
            /// </summary>
            /// <param name="data">
            /// The byte array data to be encrypted.<br></br>
            /// 要加密的字节数组数据。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The base64-encoded encrypted string.<br></br>
            /// Base64编码的加密字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string EncryptBytesToString(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(data, 0, data.Length); // 写入数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return Convert.ToBase64String(ms.ToArray()); // 返回Base64编码的加密字符串
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded encrypted string back to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将Base64编码的加密字符串解密回字节数组。
            /// </summary>
            /// <param name="encryptedData">
            /// The base64-encoded encrypted string to be decrypted.<br></br>
            /// 要解密的Base64编码的加密字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptStringToBytes(string encryptedData, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData); // 从Base64字符串转换为字节数组

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(encryptedBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                using (MemoryStream result = new MemoryStream())
                                {
                                    cs.CopyTo(result); // 复制解密后的数据到结果流
                                    return result.ToArray(); // 返回解密后的字节数组
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">
            /// The plain text string to be encrypted.<br></br>
            /// 要加密的纯文本字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="plainText"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        // 将明文字符串转换为字节数组
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(plainBytes, 0, plainBytes.Length); // 写入明文字节数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return ms.ToArray(); // 返回加密后的字节数组
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array back to a plain text string using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted plain text string.<br></br>
            /// 解密后的纯文本字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherBytes"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="cipherBytes"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(cipherBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                // 使用StreamReader读取解密后的数据
                                using (StreamReader reader = new StreamReader(cs))
                                {
                                    return reader.ReadToEnd(); // 返回解密后的明文字符串
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption and writes the encrypted data to a new file.<br></br>
            /// 使用AES加密对文件进行加密，并将加密数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行加密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption and writes the decrypted data to a new file.<br></br>
            /// 使用AES解密对文件进行解密，并将解密后的数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be decrypted.<br></br>
            /// 要解密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行解密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted data as a byte array.<br></br>
            /// 使用AES加密对字节数组进行加密，并返回加密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption and returns the decrypted data as a byte array.<br></br>
            /// 使用AES解密对字节数组进行解密，并返回解密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be decrypted.<br></br>
            /// 要解密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行解密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被解密
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.<br></br>
            /// 加密文件并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件的路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] EncryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将文件内容复制到CryptoStream中进行加密
                            fs.CopyTo(cs);
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br></br>
            /// 解密字节数组并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedData">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据的字节数组。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptBytesToFile(byte[] encryptedData, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        // 将解密后的数据从CryptoStream复制到文件中
                        cs.CopyTo(fs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br></br>
            /// 加密字节数组并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="filePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptBytesToFile(byte[] data, string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行加密
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密，并最终写入文件
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts data from a file and returns the decrypted data as a byte array.<br></br>
            /// 从文件中解密数据并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the file containing the encrypted data.<br></br>
            /// 包含加密数据的文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] DecryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行解密
                    aes.Padding = PaddingMode.ISO10126; // 使用ISO10126填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            // 从文件中读取加密数据并解密
                            cs.CopyTo(ms);
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }
        }

        /// <summary>
        /// ANSIX923 padding mode.
        /// ANSIX923 填充模式。
        /// </summary>
        public class ANSIX923
        {
            /// <summary>
            /// Encrypts the given plain text using AES encryption with the specified key and initialization vector (IV).<br></br>
            /// 使用带有指定密钥和初始化向量(IV)的AES加密对给定的明文进行加密。
            /// </summary>
            /// <param name="plainText">
            /// The plain text to encrypt.<br></br>
            /// 要加密的纯文本。
            /// </param>
            /// <param name="keyHex">
            /// The AES encryption key in hexadecimal format. Must be 64 hex characters long (32 bytes).<br></br>
            /// 十六进制AES加密密钥。必须是64个十六进制字符长(32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The initialization vector (IV) in hexadecimal format. Must be 32 hex characters long (16 bytes).<br></br>
            /// 十六进制格式的初始化向量(IV)。必须是32个十六进制字符长(16字节)。
            /// </param>
            /// <returns>
            /// The encrypted text encoded in Base64 format.<br></br>
            /// 以Base64格式编码的加密文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> is null.<br></br>
            /// 当<paramref name="plainText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> are invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出
            /// </exception>
            public static string EncryptString(string plainText, string keyHex, string ivHex)
            {
                // 检查明文是否为null
                if (plainText == null) throw new ArgumentNullException(nameof(plainText));

                // 检查密钥是否为有效的64个十六进制字符（即32字节）
                if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
                    throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));

                // 检查初始化向量（IV）是否为有效的32个十六进制字符（即16字节）
                if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32)
                    throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

                // 将十六进制格式的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    // 设置AES加密算法的密钥和初始化向量
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建加密转换器
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        // 创建CryptoStream以将数据写入内存流
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 使用StreamWriter写入明文数据
                            using (StreamWriter sw = new StreamWriter(cs))
                            {
                                sw.Write(plainText);
                            }
                        }
                        // 将加密后的数据转换为Base64字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded cipher text using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV解密base64编码的密文。
            /// </summary>
            /// <param name="cipherText">
            /// The base64-encoded encrypted text.<br></br>
            /// base64编码的加密文本。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示形式(64个十六进制字符，32字节)。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示(32个十六进制字符表示16字节)。
            /// </param>
            /// <returns>
            /// The decrypted plain text.<br></br>
            /// 解密后的纯文本。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherText"/> is null.<br></br>
            /// 当<paramref name="cipherText"/>为空时抛出。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时抛出。
            /// </exception>
            public static string DecryptString(string cipherText, string keyHex, string ivHex)
            {
                // 检查加密文本是否为空
                if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));

                // 验证密钥的长度是否为64个十六进制字符，即32字节
                if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
                    throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));

                // 验证IV的长度是否为32个十六进制字符，即16字节
                if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32)
                    throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                // 创建Aes对象来执行解密
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建解密器
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 使用MemoryStream和CryptoStream来解密数据
                    using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader sr = new StreamReader(cs))
                            {
                                // 读取并返回解密后的明文
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts byte array data to a base64-encoded string using a specified key and IV.<br></br>
            /// 将字节数组数据加密为使用指定密钥和IV的Base64编码字符串。
            /// </summary>
            /// <param name="data">
            /// The byte array data to be encrypted.<br></br>
            /// 要加密的字节数组数据。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The base64-encoded encrypted string.<br></br>
            /// Base64编码的加密字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string EncryptBytesToString(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(data, 0, data.Length); // 写入数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return Convert.ToBase64String(ms.ToArray()); // 返回Base64编码的加密字符串
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64-encoded encrypted string back to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将Base64编码的加密字符串解密回字节数组。
            /// </summary>
            /// <param name="encryptedData">
            /// The base64-encoded encrypted string to be decrypted.<br></br>
            /// 要解密的Base64编码的加密字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptStringToBytes(string encryptedData, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData); // 从Base64字符串转换为字节数组

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(encryptedBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                using (MemoryStream result = new MemoryStream())
                                {
                                    cs.CopyTo(result); // 复制解密后的数据到结果流
                                    return result.ToArray(); // 返回解密后的字节数组
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">
            /// The plain text string to be encrypted.<br></br>
            /// 要加密的纯文本字符串。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="plainText"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="plainText"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        // 将明文字符串转换为字节数组
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // 创建CryptoStream以进行加密
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(plainBytes, 0, plainBytes.Length); // 写入明文字节数据
                                cs.FlushFinalBlock(); // 完成加密操作
                                return ms.ToArray(); // 返回加密后的字节数组
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array back to a plain text string using a specified key and IV.<br></br>
            /// 使用指定的密钥和IV将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted plain text string.<br></br>
            /// 解密后的纯文本字符串。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="cipherBytes"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="cipherBytes"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(cipherBytes))
                        {
                            // 创建CryptoStream以进行解密
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                // 使用StreamReader读取解密后的数据
                                using (StreamReader reader = new StreamReader(cs))
                                {
                                    return reader.ReadToEnd(); // 返回解密后的明文字符串
                                }
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption and writes the encrypted data to a new file.<br></br>
            /// 使用AES加密对文件进行加密，并将加密数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行加密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption and writes the decrypted data to a new file.<br></br>
            /// 使用AES解密对文件进行解密，并将解密后的数据写入新文件。
            /// </summary>
            /// <param name="inputFilePath">
            /// The path to the input file to be decrypted.<br></br>
            /// 要解密的输入文件路径。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="inputFilePath"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="inputFilePath"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the files.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                    {
                        // 将输入文件内容复制到CryptoStream中进行解密，并将结果写入输出文件
                        fsInput.CopyTo(cs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted data as a byte array.<br></br>
            /// 使用AES加密对字节数组进行加密，并返回加密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] EncryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption and returns the decrypted data as a byte array.<br></br>
            /// 使用AES解密对字节数组进行解密，并返回解密后的数据作为字节数组。
            /// </summary>
            /// <param name="data">
            /// The byte array to be decrypted.<br></br>
            /// 要解密的字节数组。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            public static byte[] DecryptBytes(byte[] data, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行解密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被解密
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.<br></br>
            /// 加密文件并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the input file to be encrypted.<br></br>
            /// 要加密的输入文件的路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The encrypted byte array.<br></br>
            /// 加密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] EncryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将文件内容复制到CryptoStream中进行加密
                            fs.CopyTo(cs);
                        }
                        return ms.ToArray(); // 返回加密后的数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br></br>
            /// 解密字节数组并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedData">
            /// The byte array of encrypted data to be decrypted.<br></br>
            /// 要解密的加密数据的字节数组。
            /// </param>
            /// <param name="outputFilePath">
            /// The path to the output file where the decrypted data will be saved.<br></br>
            /// 解密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> or <paramref name="outputFilePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="encryptedData"/>、<paramref name="outputFilePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>访问文件时发生I/O错误时引发。
            /// </exception>
            public static void DecryptBytesToFile(byte[] encryptedData, string outputFilePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        // 将解密后的数据从CryptoStream复制到文件中
                        cs.CopyTo(fs);
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br></br>
            /// 加密字节数组并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">
            /// The byte array to be encrypted.<br></br>
            /// 要加密的字节数组。
            /// </param>
            /// <param name="filePath">
            /// The path to the output file where the encrypted data will be saved.<br></br>
            /// 加密后的数据将保存到的输出文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the encryption key.<br></br>
            /// 加密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="data"/> or <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="data"/>、<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static void EncryptBytesToFile(byte[] data, string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行加密
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建加密器
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream中进行加密，并最终写入文件
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都被加密
                        }
                    }
                }
            }

            /// <summary>
            /// Decrypts data from a file and returns the decrypted data as a byte array.<br></br>
            /// 从文件中解密数据并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="filePath">
            /// The path to the file containing the encrypted data.<br></br>
            /// 包含加密数据的文件路径。
            /// </param>
            /// <param name="keyHex">
            /// The hexadecimal representation of the decryption key.<br></br>
            /// 解密密钥的十六进制表示（32字节的64个十六进制字符）。
            /// </param>
            /// <param name="ivHex">
            /// The hexadecimal representation of the initialization vector.<br></br>
            /// 初始化向量的十六进制表示（16字节的32个十六进制字符）。
            /// </param>
            /// <returns>
            /// The decrypted byte array.<br></br>
            /// 解密后的字节数组。
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="filePath"/> or <paramref name="keyHex"/> or <paramref name="ivHex"/> is null.<br></br>
            /// 当<paramref name="filePath"/>、<paramref name="keyHex"/>或<paramref name="ivHex"/>为null时引发。
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="keyHex"/> or <paramref name="ivHex"/> is invalid.<br></br>
            /// 当<paramref name="keyHex"/>或<paramref name="ivHex"/>无效时引发。
            /// </exception>
            /// <exception cref="IOException">
            /// Thrown when there is an I/O error while accessing the file.<br></br>
            /// 访问文件时发生I/O错误时引发。
            /// </exception>
            public static byte[] DecryptFileToBytes(string filePath, string keyHex, string ivHex)
            {
                // 将十六进制表示的密钥和IV转换为字节数组
                byte[] key = FormattingKeyIV(keyHex, 32);
                byte[] iv = FormattingKeyIV(ivHex, 16);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC; // 使用CBC模式进行解密
                    aes.Padding = PaddingMode.ANSIX923; // 使用ANSIX923填充模式

                    // 创建解密器
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            // 从文件中读取加密数据并解密
                            cs.CopyTo(ms);
                        }
                        return ms.ToArray(); // 返回解密后的数据
                    }
                }
            }
        }
    }
}
