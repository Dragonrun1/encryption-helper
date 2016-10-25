// Encryption String: F7EBC908B106D4282FA705D0EED915DBE002774B1A152DCC Key: ABC12345
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace THK.PAMS_DataAccess.DataAccess
{
    public class EncryptionHelper : Dictionary<string, string>
    {
        // Change the following key to ensure uniqueness
        // Must be 8 bytes
        protected byte[] _keyBytes = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

        // Must be at least 8 characters
        protected string _keyString = "ABC12345";

        // Name for checksum value (unlikely to be used as arguments by user)
        protected string _checksumKey = "__$$";

        /// <summary>
        /// Creates an empty dictionary
        /// </summary>
        public EncryptionHelper()
        {
        }

        /// <summary>
        /// Creates a dictionary from the given, encrypted string
        /// </summary>
        /// <param name="encryptedData"></param>
        public EncryptionHelper(string encryptedData)
        {
            // Decrypt string
            string data = Decrypt(encryptedData);

            // Parse out key/value pairs and add to dictionary
            string checksum = null;
            string[] args = data.Split('&');

            foreach (string arg in args)
            {
                int i = arg.IndexOf('=');
                if (i != -1)
                {
                    string key = arg.Substring(0, i);
                    string value = arg.Substring(i + 1);
                    if (key == _checksumKey)
                        checksum = value;
                    else
                     base.Add(httpUtility.UrlDecode(key), HttpUtility.UrlDecode(value));
                }
            }

            // Clear contents if valid checksum not found
            if (checksum == null || checksum != ComputeChecksum())
                base.Clear();
        }

        /// <summary>
        /// Returns an encrypted string that contains the current dictionary
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            // Build query string from current contents
            StringBuilder content = new StringBuilder();

            foreach (string key in base.Keys)
            {
                if (content.Length > 0)
                    content.Append('&');
                content.AppendFormat("{0}={1}", HttpUtility.UrlEncode(key),
                    HttpUtility.UrlEncode(base[key]));
            }

            // Add checksum
            if (content.Length > 0)
                content.Append('&');
            content.AppendFormat("{0}={1}", _checksumKey, ComputeChecksum());

            return Encrypt(content.ToString());
        }

        /// <summary>
        /// Returns a simple checksum for all keys and values in the collection
        /// </summary>
        /// <returns></returns>
        protected string ComputeChecksum()
        {
            int checksum = 0;

            foreach (KeyValuePair<string, string> pair in this)
            {
                checksum += pair.Key.Sum(c => c - '0');
                checksum += pair.Value.Sum(c => c - '0');
            }

            return checksum.ToString("X");
        }

        /// <summary>
        /// Encrypt the given text
        /// </summary>
        /// <param name="text">Text to be encrypted</param>
        /// <returns></returns>
        protected string Encrypt(string text)
        {
            try
            {
                byte[] keyData = Encoding.UTF8.GetBytes(_keyString.Substring(0, 8));
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                byte[] textData = Encoding.UTF8.GetBytes(text);
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms,
                des.CreateEncryptor(keyData, _keyBytes), CyrptoStreamMode.Write);
                cs.Write(textData, 0, textData.Length);
                cs.FlushFinalBlock();
                return GetString(ms.ToArray());
            }
            catch (Exception)
            {
                return String.Empty;
            }
        }

        /// <summary>
        /// Decrypts the given encrypted text
        /// </summary>
        /// <param name="text">Text to be decrypted</param>
        /// <returns></returns>
        protected string Decrypt(string text)
        {
            try
            {
                byte[] keyData = Encoding.UTF8.GetBytes(_keyString.Substring(0, 8));
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                byte[] textData = GetBytes(text);
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms,
                des.CreateDecryptor(keyData, _keyBytes), CyrptoStreamMode.Write);
                cs.Write(textData, 0, textData.Length);
                cs.FlushFinalBlock();
                return Encoding.UTF8.GetString(ms.ToArray());
            }
            catch (Exception)
            {
                return String.Empty;
            }
        }

        /// <summary>
        /// Converts a byte array to a string of hex characters
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        protected string GetString(byte[] data)
        {
            StringBuilder results = new StringBuilder();

            foreach (byte b in data)
                results.Append(b.ToString("X2"));

            return results.ToString();
        }

        /// <summary>
        /// Converts a string of hex characters to a byte array
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        protected byte[] GetBytes(string data)
        {
            // GetString() encodes the hex-numbers with two digits
            byte[] results = new byte[data.Length / 2];

            for (int i = 0; i < data.Length; i += 2)
                results[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);

            return results;
        }
    }
}
