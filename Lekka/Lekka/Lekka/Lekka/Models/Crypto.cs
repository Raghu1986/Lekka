using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace Lekka.Models
{
    public class Crypto
    {
        private static byte[] Values = { 1,4,8,15,56,213,42,108, 1, 4, 18, 15, 16, 23, 142, 108,
                                         1,24,8,15,16,213,42,108, 1, 24, 8, 15, 16, 213, 42, 108};
        private static SymmetricKeyAlgorithmProvider Algorithm = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);

        private static CryptographicKey Ckey = Algorithm.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(Values));

        private static IBuffer Ib = Values.AsBuffer();


        public static string Encrypt(string RawData)
        {
            string Encrp = "";
            try
            {
                IBuffer buffer = CryptographicBuffer.ConvertStringToBinary(RawData, BinaryStringEncoding.Utf8);
                IBuffer bufferEncrypt = CryptographicEngine.Encrypt(Ckey, buffer, Ib);
                Encrp = CryptographicBuffer.EncodeToBase64String(bufferEncrypt);
            }
            catch
            {
                Encrp = "error!";
            }

            return Encrp;
            
        }

        public static string Decrypt(string EncrpData)
        {
            string Decrp = "";
            try
            {
                IBuffer buffer =Convert.FromBase64String(EncrpData).AsBuffer();
                IBuffer bufferDecrypt = CryptographicEngine.Decrypt(Ckey, buffer, Ib);
                Decrp = CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8,bufferDecrypt);
            }
            catch
            {
                Decrp = "error!";
            }

            return Decrp;

        }
        

    }
}
