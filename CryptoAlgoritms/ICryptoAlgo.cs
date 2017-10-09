using Cryptography.CryptoAlgoritms.Domain;
using System;
using System.Collections.Generic;
using System.Text;

namespace Cryptography.CryptoAlgoritms
{
    public interface ICryptoAlgo
    {

        void ChooseMode(CryptoStatus status);
        void WriteCryptoToFile();
    }
}
