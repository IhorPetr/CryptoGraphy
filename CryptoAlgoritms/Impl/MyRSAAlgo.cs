using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Cryptography.CryptoAlgoritms.Domain;

namespace Cryptography.CryptoAlgoritms.Impl
{
    public class MyRSAAlgo : ICryptoAlgo,IDisposable
    {
        private RSACryptoServiceProvider myTripleRSA;
        private SafeHandle resource;
        private byte[] encrypted;
        public string Message { get; set; }
        public MyRSAAlgo()
        {
            this.myTripleRSA=new RSACryptoServiceProvider();
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
        public void EncryptStringToBytes()
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(Message);
            try
            {

               this.myTripleRSA.ImportParameters(this.myTripleRSA.ExportParameters(false));

                encrypted = this.myTripleRSA.Encrypt(dataToEncrypt, false);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }
        }
        public void WriteCryptoToFile()
        {
            if (encrypted.Length == 0)
                throw new ArgumentNullException("EmptyString");
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\Files\\CryptoFile.txt", encrypted);
        }
        public void DecryptStringFromBytes()
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            try
            {
                string plaintext = null;
                byte[] dataToDecript=null;
                this.myTripleRSA.ImportParameters(this.myTripleRSA.ExportParameters(true));

                dataToDecript = this.myTripleRSA.Decrypt(encrypted, false);
                plaintext = ByteConverter.GetString(dataToDecript);
                Console.WriteLine($"Result encryption is: {plaintext}");
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }
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
