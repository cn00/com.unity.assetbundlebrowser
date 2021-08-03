using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine.Assertions;

namespace AssetBundleBrowser
{
    /// <summary>
    /// Stream从开头指定byte只有分钟xor一边…一边Read/Write薄，薄Stream
    /// Writeでbyte通过数组byte注意排列内容被污染
    /// </summary>
    public sealed class MaskedHeaderStream : Stream
    {
        /// <summary>
        /// 1byte只看ReadByte/WriteByte方法用Buffer
        /// </summary>
        [ThreadStatic]
        private static byte[] _sharedByteBuffer;

        /// <summary>
        /// Stream从开头仅此长度xor被，被
        /// </summary>
        private readonly long _headerLength;

        /// <summary>
        /// xor的一侧
        /// </summary>
        private readonly byte[] _maskBytes;

        /// <summary>
        /// _maskBytes从开头只有这个长度xor被利用
        /// </summary>
        private readonly long _maskLength;

        /// <summary>
        /// xorのbyte数组的生成源字符串
        /// </summary>
        private readonly string _maskString;

        /// <summary>
        /// xor已完成(被，被)Stream
        /// </summary>
        private readonly Stream _baseStream;

        public override bool CanRead => _baseStream.CanRead;
        public override bool CanSeek => _baseStream.CanSeek;
        public override bool CanWrite => _baseStream.CanWrite;
        public override bool CanTimeout => _baseStream.CanTimeout;
        public override long Length => _baseStream.Length;

        public override int ReadTimeout
        {
            get => _baseStream.ReadTimeout;
            set => _baseStream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _baseStream.WriteTimeout;
            set => _baseStream.WriteTimeout = value;
        }

        public override long Position
        {
            get => _baseStream.Position;
            set => _baseStream.Position = value;
        }

        /// <summary>
        /// 整个xor mask可移动的构造器
        /// </summary>
        /// <param name="baseStream">Read/Write对象的Stream</param>
        /// <param name="maskBytes">xor mask数据</param>
        public MaskedHeaderStream(Stream baseStream, byte[] maskBytes)
            : this(baseStream, long.MaxValue, maskBytes, maskBytes?.LongLength ?? 0L)
        {
        }

        /// <summary>
        /// xor mask指定数据长度的构造器
        /// </summary>
        /// <param name="baseStream">Read/Write对象的Stream</param>
        /// <param name="headerLength">Stream开头几个字节xor mask的对象 整个xor想做的时候long.MaxValue但是吐槽</param>
        /// <param name="maskBytes">xor mask数据</param>
        /// <param name="maskLength">xor mask的第几字节</param>
        public MaskedHeaderStream(Stream baseStream, long headerLength, byte[] maskBytes, long maskLength)
        {
            Assert.IsNotNull(baseStream);
            Assert.IsNotNull(maskBytes);
            Assert.IsTrue(maskLength <= maskBytes.Length);
            _baseStream = baseStream;
            _headerLength = headerLength;
            _maskBytes = maskBytes;
            _maskLength = maskLength;
        }

        public MaskedHeaderStream(Stream baseStream, long headerLength, string maskString)
        {
            Assert.IsNotNull(baseStream);
            Assert.IsNotNull(maskString);
            _baseStream = baseStream;
            _headerLength = headerLength;
            _maskString = maskString;
        }

        /// <summary>
        /// xor mask执行程序
        /// streamPosが_headerLength一过了车站就什么也不做了
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Crypt(byte[] buffer, int offset, int count, long streamPos)
        {
            if (_maskString != null)
            {
                CryptByString(buffer, offset, count, streamPos, _headerLength, _maskString);
            }
            else
            {
                CryptByByteArray(buffer, offset, count, streamPos, _headerLength, _maskBytes, _maskLength);
            }
        }

        /// <summary>
        /// 从字符串中独立byte生成数组
        /// </summary>
        internal static byte[] StringToMaskBytes(string maskString)
        {
            if (maskString == null)
            {
                return new byte[0];
            }

            unsafe
            {
                var bytesLength = maskString.Length * 2;
                var maskBytes = stackalloc byte[bytesLength];
                StringToMaskBytes(maskString, maskBytes, bytesLength);
                var bytes = new byte[bytesLength];
                Marshal.Copy((IntPtr) maskBytes, bytes, 0, bytesLength);
                return bytes;
            }
        }

        /// <summary>
        /// string生成难读化/解码的键排列
        /// </summary>
        /// <param name="maskString">难读关键字字符串</param>
        /// <param name="maskBytes">由难读密钥字符串生成的byte排列位置</param>
        /// <param name="bytesLength">字节排列大小</param>
        private static unsafe void StringToMaskBytes(string maskString, byte* maskBytes, int bytesLength)
        {
            Assert.IsNotNull(maskString);
            var sourceLength = maskString.Length;

            // string从…开始byte生成数组
            // ex) "xyz" => [ 'x', '~z', 'y', '~y', 'z', '~z']
            // 但是bytesLengthとmaskString.Length*2不一致的时候，要素会被埋、埋不住、或者被覆盖，感觉有点奇怪
            var bytesTailIndex = bytesLength - 1;
            for (var i = 0; i < sourceLength; ++i)
            {
                // stringのindex访问时间callvirt因为是命令1关于文字1想抑制回数
                var v = (byte) maskString[i];
                // 偶数号是source的字符串从开头开始填充
                maskBytes[i * 2] = v;
                // 文字从结尾处翻转到奇数个元素byte逐渐填满价值
                maskBytes[bytesTailIndex - (i * 2)] = (byte) ~v;
            }

            // byte从数组hash创建
            var baseHash = BytesToHash(maskBytes, bytesLength);

            // byte排列hash按数值xor
            for (var i = 0; i < bytesLength; i++)
            {
                maskBytes[i] = (byte) (maskBytes[i] ^ baseHash);
            }
        }

        /// <summary>
        /// xor mask执行程序
        /// streamPosが_headerLength一过了车站就什么也不做了
        /// </summary>
        public static void CryptByString(
            byte[] buffer,
            int offset,
            int count,
            long streamPos,
            long headerLength,
            string maskString)
        {
            var headPos = streamPos;
            var bufferPos = offset;
            var loopCount = 0;
            if (string.IsNullOrEmpty(maskString))
            {
                return;
            }

            if (headPos >= headerLength || bufferPos >= buffer.Length)
            {
                return;
            }

            unsafe
            {
                var bytesLength = maskString.Length * 2;
                var maskBytes = stackalloc byte[bytesLength];
                StringToMaskBytes(maskString, maskBytes, bytesLength);
                while (headPos < headerLength && bufferPos < buffer.Length && loopCount < count)
                {
                    buffer[bufferPos] ^= maskBytes[headPos % bytesLength];
                    ++bufferPos;
                    ++headPos;
                    ++loopCount;
                }
            }
        }

        /// <summary>
        /// xor mask执行程序
        /// streamPosが_headerLength一过了车站就什么也不做了
        /// </summary>
        internal static void CryptByByteArray(
            byte[] buffer,
            int offset,
            int count,
            long streamPos,
            long headerLength,
            byte[] maskBytes,
            long maskLength)
        {
            var headPos = streamPos;
            var bufferPos = offset;
            var loopCount = 0;
            if (maskLength == 0)
            {
                return;
            }

            while (headPos < headerLength && bufferPos < buffer.Length && loopCount < count)
            {
                buffer[bufferPos] ^= maskBytes[headPos % maskLength];
                ++bufferPos;
                ++headPos;
                ++loopCount;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _baseStream.Dispose();
            }

            base.Dispose(disposing);
        }

        public override void Flush()
        {
            _baseStream.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return _baseStream.FlushAsync(cancellationToken);
        }

        public override void SetLength(long value)
        {
            _baseStream.SetLength(value);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _baseStream.Seek(offset, origin);
        }

        public override int ReadByte()
        {
            _sharedByteBuffer = _sharedByteBuffer ?? new byte[1];
            if (Read(_sharedByteBuffer, 0, 1) == 0)
            {
                return -1;
            }

            return _sharedByteBuffer[0];
        }

        public override void WriteByte(byte value)
        {
            _sharedByteBuffer = _sharedByteBuffer ?? new byte[1];
            _sharedByteBuffer[0] = value;
            Write(_sharedByteBuffer, 0, 1);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var streamPos = Position;
            var ret = _baseStream.Read(buffer, offset, count);
            Crypt(buffer, offset, count, streamPos);

            if (streamPos == 0 && offset == 0)
            {
                // 仅开头字节的特殊处理
                buffer[0] = (byte)'U';
            }

            return ret;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Crypt(buffer, offset, count, Position);
            _baseStream.Write(buffer, offset, count);
        }

        public override async Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var streamPos = Position;
            var readCount = await _baseStream.ReadAsync(buffer, offset, count, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            Crypt(buffer, offset, count, streamPos);
            return readCount;
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Crypt(buffer, offset, count, Position);
            await _baseStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override IAsyncResult BeginRead(
            byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            var streamPos = Position;
            return _baseStream.BeginRead(buffer, offset, count, ar =>
            {
                Crypt(buffer, offset, count, streamPos);
                callback?.Invoke(ar);
            }, state);
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            return _baseStream.EndRead(asyncResult);
        }

        public override IAsyncResult BeginWrite(
            byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            Crypt(buffer, offset, count, Position);
            return _baseStream.BeginWrite(buffer, offset, count, callback, state);
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            _baseStream.EndWrite(asyncResult);
        }

        public override object InitializeLifetimeService()
        {
            return _baseStream.InitializeLifetimeService();
        }

        /// <summary>
        /// byte配列pointer从…开始byte区域中的hash计算值
        /// </summary>
        internal static unsafe int BytesToHash(byte* bytes, int byteLength)
        {
            var hash = 0xBB;
            // 一边向右移动xor取得
            for (var i = 0; i < byteLength; ++i)
            {
                var value = bytes[i];
                hash = ((hash >> 1) | ((hash & 0x1) << 7)) ^ value;
            }

            return hash;
        }
    }
}
