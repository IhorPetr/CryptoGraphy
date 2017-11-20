using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Cryptography.CryptoAlgoritms.Domain;

namespace Cryptography.CryptoAlgoritms.Impl
{
    public class MyMD5Algo : IDisposable,ICryptoAlgo
    {
        private MD5CryptoServiceProvider myTripleMD5;
        private SafeHandle resource;
        public string hash;
        public string Message { get; set; }
        public MyMD5Algo()
        {
            this.myTripleMD5=new MD5CryptoServiceProvider();
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
            if (String.IsNullOrEmpty(hash))
                throw new ArgumentNullException("EmptyString");
            File.WriteAllText(Directory.GetCurrentDirectory() + "\\Files\\CryptoFile.txt", hash);
        }

        public string getMd5Hash(string input)
        {
            byte[] data = myTripleMD5.ComputeHash(Encoding.Default.GetBytes(Message));
            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        public void verifyMd5Hash(string input,string hash)
        {
            // Hash the input.
            string hashOfInput = getMd5Hash(input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                Console.WriteLine("The hashes are the same.");
            }
            else
            {
                Console.WriteLine("The hashes are not same.");
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
