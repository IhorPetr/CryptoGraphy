using System;
using System.Collections.Generic;
using System.Text;
using KalynaCipher.Model;

namespace KalynaCipher
{
    public interface IKalina
    {
        KalynaModel KalynaInit(UInt32 block_size, UInt32 key_size);
        void KalynaKeyExpand(UInt64 key, KalynaModel ctx);
        void KalynaEncipher(UInt64 plaintext, KalynaModel ctx, UInt64 ciphertext);
        void KalynaDecipher(UInt64 ciphertext, KalynaModel ctx, UInt64 plaintext);
    }
}
