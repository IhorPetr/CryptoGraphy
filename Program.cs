using System;
using System.Text;
using System.Security.Cryptography;
using Cryptography.CryptoAlgoritms;
using Cryptography.CryptoAlgoritms.Domain;
using System.Collections.Generic;
using System.Linq;
using Cryptography.CryptoAlgoritms.Impl;

namespace Cryptography
{
    class Program
    {
        static void Main(string[] args)
        {
            do
            {
                Console.WriteLine("Choose Crypto Algoritm");
                Console.WriteLine("1:DES");
                Console.WriteLine("2:AES");
                switch (Console.ReadLine())
                {
                    case "1":
                        var result = ChooseMode<MyDESAlgo>();
                        ChooseSource(result);
                        result.EncryptStringToBytes();
                        WriteCryptoToFile(result);
                        result.DecryptStringFromBytes();
                        break;
                    case "2":
                        var res = ChooseMode<MyAESAlgo>();
                        break;
                    default:
                        Console.WriteLine("Unknown command");
                        break;
                }
            } while (Console.ReadLine()!="N");
        }
        static T ChooseMode<T>() where T : MyAESAlgo,MyDESAlgo,  new()
        {
            do
            {
                Console.WriteLine("Choose Mode to Encrypt:");
                Console.WriteLine("1:CBC");
                Console.WriteLine("2:CTS");
                Console.WriteLine("3:ECB");
                switch(Console.ReadLine())
                {
                    case "1":
                        var res = EnterKey();
                        return new T() { mode = CipherMode.CBC, key = res.key, LenthKey=res.length };
                    case "2":
                        var rest = EnterKey();
                        return new T() { mode = CipherMode.CTS, key = rest.key, LenthKey = rest.length };
                    case "3":
                        var resp = EnterKey();
                        return new T() { mode = CipherMode.ECB, key = resp.key, LenthKey = resp.length };
                    default:
                        Console.WriteLine("Unknown command");
                        break;
                }
            } while (true);
            
        }
        static (byte[] key,int length) EnterKey()
        {
            Console.WriteLine("Do you Want Enter Secret Key?");
            var result = (key:new byte[0], length:0);
            if(Console.ReadLine()=="Y")
            {

                Console.Write("Enter Length your secret key: ");
                result.length = Convert.ToInt32(Console.ReadLine());
                result.key = new byte[0];
                while (result.key.Length!= result.length)
                {
                    Console.Write("Enter your secret key: ");
                    result.key = Encoding.ASCII.GetBytes(Console.ReadLine());
                    if(result.key.Length!= result.length)
                    {
                        Console.WriteLine($"Invalid key,your key should have size {result.length}, but your {result.key.Length}");
                    }
                }
                result.length *= 8;
                return result;
            }
            return result;
        }
        static void ChooseSource(ICryptoAlgo choose)
        {
            do
            {
                Console.WriteLine("Choose source your data:");
                Console.WriteLine("1:From File");
                Console.WriteLine("2:From Console");
                switch(Console.ReadLine())
                {
                    case "1":
                        choose.ChooseMode(CryptoStatus.File);
                        return;
                    case "2":
                        choose.ChooseMode(CryptoStatus.Personal);
                        return;
                }
            } while (true);
        }
        static void WriteCryptoToFile(ICryptoAlgo crypto)
        {
            Console.WriteLine("Do you Write Crypto to File?");
            if (Console.ReadLine() == "Y")
            {
                crypto.WriteCryptoToFile();
            }
         }
    }
}
