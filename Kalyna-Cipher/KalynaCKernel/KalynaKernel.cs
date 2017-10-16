using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace KalynaCipher.KalynaCKernel
{
    public class KalynaKernel
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int MultiplyByTen(int numberToMultiply);

        public KalynaKernel()
        {
            IntPtr pDll = NativeMethods.LoadLibrary(Directory.GetCurrentDirectory() + "\\x64\\Release\\KalynaByC.dll");

            if (pDll == IntPtr.Zero) throw new ApplicationException();

            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(pDll, "MultiplyByTen");

            if(pAddressOfFunctionToCall == IntPtr.Zero) throw new ApplicationException();

            MultiplyByTen multiplyByTen = (MultiplyByTen)Marshal.GetDelegateForFunctionPointer(
                pAddressOfFunctionToCall,
                typeof(MultiplyByTen));
        }
    }
}
