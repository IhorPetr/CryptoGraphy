using Cryptography.CryptoAlgoritms.Domain;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography.CryptoAlgoritms.Impl
{
    public class MyAESAlgo : IDisposable,ICryptoAlgo
    {
        private SafeHandle resource;
        private Aes myTripleAES;
        public string Message { get; set; }
        private byte[] encrypted;
        public int LenthKey { get; set; }
        public CipherMode mode { get; set; }
        public byte[] key { get; set; }
        public MyAESAlgo()
        {
            this.myTripleAES = Aes.Create();
        }

        public void EncryptStringToBytes()
        {
            if (Message == null || Message.Length <= 0)
                throw new ArgumentNullException("EmptyLengMessage");
            if (key.Length != 0)
            {
                myTripleAES.KeySize = LenthKey;
                myTripleAES.Key = key;
                myTripleAES.Mode = mode;
            }
            ICryptoTransform encryptor = myTripleAES.CreateEncryptor(myTripleAES.Key, myTripleAES.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(Message);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }
        public void DecryptStringFromBytes()
        {
            if (Message == null || Message.Length <= 0)
                throw new ArgumentNullException("EmptyLengMessage");
            if (encrypted == null || encrypted.Length == 0)
                throw new ArgumentNullException("EmptyEncryptor");

            string plaintext = null;

            ICryptoTransform decryptor = myTripleAES.CreateDecryptor(myTripleAES.Key, myTripleAES.IV);

            using (MemoryStream msDecrypt = new MemoryStream(encrypted))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            Console.WriteLine($"Result encryption is: {plaintext}");

        }
        public void ChooseMode(CryptoStatus status)
        {
            switch (status)
            {
                case CryptoStatus.File:
                    Message = File.ReadAllText(Directory.GetCurrentDirectory() + "\\Files\\Information.txt");
                    break;
                case CryptoStatus.Personal:
                    Console.WriteLine("Enter Informations to encrypt");
                    Message = Console.ReadLine();
                    break;
            }
        }
        public void WriteCryptoToFile()
        {
            if (encrypted.Length == 0)
                throw new ArgumentNullException("EmptyString");
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\Files\\CryptoFile.txt", encrypted);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (resource != null) resource.Dispose();
            }
        }
    }
}
