using System;
using System.IO;
using System.Runtime.CompilerServices;
using UnityEngine.Assertions;

 namespace AssetBundleBrowser
 {
     /// <summary>
     /// 難読化Stream解密文件Stream构筑，构筑
     /// </summary>
     public static class MaskedHeaderStreamUtility
     {
         public enum CryptType : byte
         {
             Raw,
             Version1 = (byte)'1',
             Version1Full = (byte)'2',
         }

         /// <summary>
         /// 难读化对象的范围
         /// </summary>
         public static readonly int DefaultHeaderLength = 256;

         /// <summary>
         /// UnityFS, UnityWeb, UnityRaw, UnityArchive 中的共同部分Unity只有
         /// </summary>
         private static readonly byte[] UnitySignature = {(byte)'U'};

         /// <summary>
         /// 先頭5byte只舔buffer
         /// </summary>
         [ThreadStatic] private static byte[] _signatureBuffer;

         /// <summary>
         /// 被交付了byte排头5byte因此，已将其难读化的byte判定是否排列
         /// AssetBundle用于构建环境internal
         /// </summary>
         public static bool IsEncryptedStreamBytes(byte[] headerBytes, int headerLength)
         {
             Assert.IsNotNull(headerBytes, "headerBytes != null");
             Assert.IsFalse(headerBytes.Length < headerLength, "headerBytes.Length < headerLength");
             if (headerLength < UnitySignature.Length)
             {
                 // 太短了
                 return false;
             }

             for (var i = 0; i < UnitySignature.Length; i++)
             {
                 // "Unity"如果不是以文字开始的话true
                 if (headerBytes[i] != UnitySignature[i])
                 {
                     return true;
                 }
             }

             // "Unity"开始的文件是明文处理
             return false;
         }

         /// <summary>
         /// 被交付了stream判定是否已禁用
         /// </summary>
         internal static bool IsEncryptedStream(Stream stream)
         {
             Assert.IsNotNull(stream, "stream != null");
             _signatureBuffer = _signatureBuffer ?? new byte[UnitySignature.Length];
             var beforePos = stream.Position;
             stream.Position = 0;
             var readCount = stream.Read(_signatureBuffer, 0, _signatureBuffer.Length);
             // 回到原来的位置
             stream.Position = beforePos;
             return readCount == _signatureBuffer.Length
                    && IsEncryptedStreamBytes(_signatureBuffer, readCount);
         }

         internal static CryptType GetCryptType(Stream stream)
         {
             Assert.IsNotNull(stream, "stream != null");
             _signatureBuffer = _signatureBuffer ?? new byte[UnitySignature.Length];
             var beforePos = stream.Position;
             stream.Position = 0;
             var readCount = stream.Read(_signatureBuffer, 0, _signatureBuffer.Length);
             // 回到原来的位置
             stream.Position = beforePos;
             return GetCryptType(_signatureBuffer[0]);
         }

         private static CryptType GetCryptType(byte b)
         {
             switch (b)
             {
                 case (byte)'U':
                     return CryptType.Raw;
                 case (byte)CryptType.Version1:
                     return CryptType.Version1;
                 case (byte)CryptType.Version1Full:
                     return CryptType.Version1Full;
             }

             return CryptType.Raw;
         }

         /// <summary>
         /// 从字符串中独立byte生成数组
         /// </summary>
         internal static byte[] CreateHashMaskBytes(string source)
         {
             return MaskedHeaderStream.StringToMaskBytes(source);
         }

         /// <summary>
         /// byte从数组byte区域中的hash计算值
         /// </summary>
         [MethodImpl(MethodImplOptions.AggressiveInlining)]
         internal static int BytesToHash(byte[] bytes)
         {
             unsafe
             {
                 fixed (byte* p = bytes)
                 {
                     return MaskedHeaderStream.BytesToHash(p, bytes.Length);
                 }
             }
         }
     }
 }
