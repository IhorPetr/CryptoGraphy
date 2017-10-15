using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using KalynaCipher.Model;

namespace KalynaCipher
{
    public class Kalina : IKalina
    {
        public KalynaModel KalynaInit(UInt32 block_size, UInt32 key_size)
        {
            var  ctx=new KalynaModel();
            if (block_size== KalynaConsts.kBLOCK_128)
            {
                ctx.nb = KalynaConsts.kBLOCK_128 / KalynaConsts.kBITS_IN_WORD;
                if (key_size==KalynaConsts.kKEY_128)
                {
                    ctx.nk= KalynaConsts.kKEY_128 / KalynaConsts.kBITS_IN_WORD;
                    ctx.nr = KalynaConsts.kNR_128;
                }
                else if (key_size == KalynaConsts.kKEY_256)
                {
                    ctx.nk = KalynaConsts.kKEY_256 / KalynaConsts.kBITS_IN_WORD;
                    ctx.nr = KalynaConsts.kNR_256;
                }
                else
                {
                    throw new CryptographicException("Error: unsupported key size");
                }
            }
            else if(block_size== KalynaConsts.kBLOCK_256)
            {
                ctx.nb = KalynaConsts.kBLOCK_256 / KalynaConsts.kBITS_IN_WORD;
                if (key_size==KalynaConsts.kKEY_256)
                {
                    ctx.nk = KalynaConsts.kKEY_256 / KalynaConsts.kBITS_IN_WORD;
                    ctx.nr = KalynaConsts.kNR_256;
                }
                else if (block_size==KalynaConsts.kKEY_512)
                {
                    ctx.nk = KalynaConsts.kKEY_512 / KalynaConsts.kBITS_IN_WORD;
                    ctx.nr = KalynaConsts.kNR_512;
                }
                else
                {
                    throw new CryptographicException("Error: unsupported key size");
                }
            }
            else if(block_size == KalynaConsts.kBLOCK_512)
            {
                ctx.nb = KalynaConsts.kBLOCK_512 / KalynaConsts.kBITS_IN_WORD;
                if (key_size== KalynaConsts.kKEY_512)
                {
                    ctx.nb = KalynaConsts.kBLOCK_512 / KalynaConsts.kBITS_IN_WORD;
                    ctx.nr = KalynaConsts.kNR_512;
                }
                else
                {
                    throw new CryptographicException("Error: unsupported key size");
                }
            }
            else
            {
                throw new CryptographicException("Error: unsupported key size");
            }
            ctx.state = new UInt64[] { };
            ctx.round_keys = new UInt64[,] { };
            return ctx;
        }

        public void SubBytes(KalynaModel ctx)
        {
            UInt64[] s = ctx.state;
            for (int i = 0; i < ctx.nb; ++i)
            {
                ctx.state[i]= MatrixModel
            }
        }

    }
}
