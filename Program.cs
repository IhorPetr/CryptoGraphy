using System;
using System.Text;
using System.Security.Cryptography;
using Cryptography.CryptoAlgoritms;
using Cryptography.CryptoAlgoritms.Domain;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
                Console.WriteLine("3:RSA");
                Console.WriteLine("4:MD5");
                switch (Console.ReadLine())
                {
                    case "1":
                        var result = ChooseMode<MyDESAlgo>();
                        result.obj.key = result.key;
                        result.obj.LenthKey = result.length;
                        result.obj.mode = result.mode;
                        ChooseSource(result.obj);
                        result.obj.EncryptStringToBytes();
                        WriteCryptoToFile(result.obj);
                        result.obj.DecryptStringFromBytes();
                        break;
                    case "2":
                        var res = ChooseMode<MyAESAlgo>();
                        res.obj.key = res.key;
                        res.obj.LenthKey = res.length;
                        res.obj.mode = res.mode;
                        ChooseSource(res.obj);
                        res.obj.EncryptStringToBytes();
                        WriteCryptoToFile(res.obj);
                        res.obj.DecryptStringFromBytes();
                        break;
                    case "3":
                        var algo = new MyRSAAlgo();
                        algo.EncryptStringToBytes();
                        WriteCryptoToFile(algo);
                        algo.DecryptStringFromBytes();
                        break;
                    case "4":
                        var MDA5 = new MyMD5Algo();
                        MDA5.hash = MDA5.getMd5Hash(MDA5.Message);
                        WriteCryptoToFile(MDA5);
                        Console.WriteLine("Write message to compare the hash");
                        MDA5.verifyMd5Hash(Console.ReadLine(),MDA5.hash);
                        break;
                    default:
                        Console.WriteLine("Unknown command");
                        break;
                }
                Console.WriteLine("Do you want Leave Program?[Y/N]");
            } while (Char.ToUpper(Convert.ToChar(Console.Read())) !=  'N');
        }
        static (T obj, CipherMode mode, byte[] key, int length) ChooseMode<T>() where T : ICryptoAlgo,  new()
        {
            do
            {
                var result = (obj: new T(), mode: CipherMode.CBC, key: new byte[0], length: 0);
                Console.WriteLine("Choose Mode to Encrypt:");
                Console.WriteLine("1:CBC");
                Console.WriteLine("2:CTS");
                Console.WriteLine("3:ECB");
                switch(Console.ReadLine())
                {
                    case "1":
                        var res = EnterKey();
                        result.mode = CipherMode.CBC;
                        result.key = res.key;
                        result.length = res.length;
                        return result;
                    case "2":
                        var rep = EnterKey();
                        result.mode = CipherMode.CTS;
                        result.key = rep.key;
                        result.length = rep.length;
                        return result;
                    case "3":
                        var reps = EnterKey();
                        result.mode = CipherMode.ECB;
                        result.key = reps.key;
                        result.length = reps.length;
                        return result;
                    default:
                        Console.WriteLine("Unknown command");
                        break;
                }
            } while (true);
            
        }
        static (byte[] key,int length) EnterKey()
        {
            Console.WriteLine("Do you Want Enter Secret Key?[Y/N]");
            var result = (key:new byte[0], length:0);
            if(Char.ToUpper(Convert.ToChar(Console.Read())) != 'Y')
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
            Console.WriteLine("Do you Write Crypto to File?[Y/N]");
            if (Char.ToUpper(Convert.ToChar(Console.Read())) != 'Y')
            {
                crypto.WriteCryptoToFile();
            }
         }
    }
}
