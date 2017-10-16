using System;
using System.Collections.Generic;
using System.Text;

namespace KalynaCipher.KalynaSharp.Model
{
    public class KalynaModel
    {
        public UInt32 nb { get; set; }
        public UInt32 nk { get; set; }
        public UInt32 nr { get; set; }
        public UInt64[] state { get; set; }
        public UInt64[,] round_keys { get; set; }
    }
}
