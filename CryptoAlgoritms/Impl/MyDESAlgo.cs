using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Cryptography.CryptoAlgoritms.Domain;
using System.IO;

namespace Cryptography.CryptoAlgoritms
{
    public class MyDESAlgo : IDisposable, ICryptoAlgo
    {
        private SafeHandle resource;
        private DESCryptoServiceProvider myTripleDES;
        public string Message { get; set; }
        private byte[] encrypted;
        public int LenthKey { get; set; }
        public CipherMode mode { get; set; }
        public byte[] key { get; set; }
        public MyDESAlgo()
        {
            this.myTripleDES = new DESCryptoServiceProvider();
        }
        public void ChooseMode(CryptoStatus status)
        {
            switch(status)
            {
                case CryptoStatus.File:
                    Message = File.ReadAllText(Directory.GetCurrentDirectory()+"\\Files\\Information.txt");
                    break;
                case CryptoStatus.Personal:
                    Console.WriteLine("Enter Informations to encrypt");
                    Message= Console.ReadLine();
                    break;
            }
        }
        public void EncryptStringToBytes()
        {
            if (Message == null || Message.Length <= 0)
                throw new ArgumentNullException("EmptyLengMessage");

            if (key.Length != 0)
            {
                myTripleDES.KeySize = LenthKey;
                myTripleDES.Key = key;
                myTripleDES.Mode = mode;
            }



                ICryptoTransform encryptor = myTripleDES.CreateEncryptor(myTripleDES.Key, myTripleDES.IV);


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
        public void WriteCryptoToFile()
        {
            if(encrypted.Length==0)
                throw new ArgumentNullException("EmptyString");
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\Files\\CryptoFile.txt", encrypted);
        }
        public void DecryptStringFromBytes()
        {
            if (Message == null || Message.Length <= 0)
                throw new ArgumentNullException("EmptyLengMessage");
            if (encrypted == null || encrypted.Length == 0)
                throw new ArgumentNullException("EmptyEncryptor");

            string plaintext = null;




                ICryptoTransform decryptor = myTripleDES.CreateDecryptor(myTripleDES.Key, myTripleDES.IV);

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
