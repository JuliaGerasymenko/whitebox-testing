using System;
using Xunit;
using IIG.PasswordHashingUtils;
using System.ComponentModel;

namespace whitebox_testing.Tests
{
    public class UnitTest1
    {
        [Fact]
        public void Test_GetHash_CheckType_True()
        {

          IIG.PasswordHashingUtils.PasswordHasher.Init("a", 2);
          var generated_hash = IIG.PasswordHashingUtils.PasswordHasher.GetHash("password","1", 0x0071003f);
          Assert.True(generated_hash is string);
        }
        [Fact]
        public void PasswordHasher_GetHash_Compare_True()
        {

            var a = "a";
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var adler32checkSum = 50;
            var generated_hash = IIG.PasswordHashingUtils.PasswordHasher.GetHash(a, "1", 50);
            var generated_hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(a, "1", 510);
            Assert.Equal(generated_hash, generated_hash1);
        }
        [Fact]
        public void PasswordHasher_GetHash_NoSalt_True()
        {
            var a = "a";
            var hash = IIG.PasswordHashingUtils.PasswordHasher.GetHash(a, null, 0);
            Assert.Equal("ABFF2389D651B2F7B68D4A4808DA1AD31C6C09B9378E0C9B373082ADA2C9ABEE", hash);
        }
        [Fact]
        public void PasswordHasher_GetHash_CompareLetterA_True()
        {
            var a = "a";
            var french_a = "à";
            var hash_a = IIG.PasswordHashingUtils.PasswordHasher.GetHash(a, null, 0);
            var hash_french_a = IIG.PasswordHashingUtils.PasswordHasher.GetHash(french_a, null, 0);
            Assert.NotEqual(a, french_a);
        }
        [Fact]
        public void PasswordHasher_HashSha2_CompareEqual_True()
        {
            var a = "a";
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("HashSha2", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal = Adler32CheckSumMethod.Invoke(null, new object[]{a});
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{a});
            Assert.Equal(Adler32CheckSumVal, Adler32CheckSumVal2);
        }
        [Fact]
        public void PasswordHasher_HashSha2_CompareNotEqual_True()
        {
            var a = "a";
            var b = "b";
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("HashSha2", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal = Adler32CheckSumMethod.Invoke(null, new object[]{a});
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{b});
            Assert.NotEqual(Adler32CheckSumVal, Adler32CheckSumVal2);
        }
        [Fact]
        public void PasswordHasher_HashSha2_CompareEqual_DifferInit_True()
        {
            var a = "a";
            var b = "b";
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            
            var Adler32CheckSumMethod = type.GetMethod("HashSha2", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            IIG.PasswordHashingUtils.PasswordHasher.Init("null123" ,7);
            var Adler32CheckSumVal = Adler32CheckSumMethod.Invoke(null, new object[]{a});
            IIG.PasswordHashingUtils.PasswordHasher.Init("null" ,3);
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{a});
            Assert.Equal(Adler32CheckSumVal, Adler32CheckSumVal2);
        }
        [Fact]
        public void PasswordHasher_HashSha2_CompareNotEqualLetterA_True()
        {
            var a = "a";
            var french_a = "à";
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            
            var Adler32CheckSumMethod = type.GetMethod("HashSha2", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            IIG.PasswordHashingUtils.PasswordHasher.Init("null123" ,7);
            var Adler32CheckSumVal = Adler32CheckSumMethod.Invoke(null, new object[]{a});
            IIG.PasswordHashingUtils.PasswordHasher.Init("null" ,3);
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{french_a});
            Assert.NotEqual(Adler32CheckSumVal, Adler32CheckSumVal2);
        }
        [Fact]
        public void PasswordHasher_Adler32CheckSum_NegativeIndexLength_True()
        {

            var a = "a";
           
            IIG.PasswordHashingUtils.PasswordHasher.Init(null ,4);

            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("Adler32CheckSum", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
           
            var Adler32CheckSumVal = Adler32CheckSumMethod.Invoke(null, new object[]{a, -1, -1});
            Assert.Equal("01000000", Adler32CheckSumVal);
        }
        [Fact]
        public void PasswordHasher_Adler32CheckSum_NullIndexLength_True()
        {
            var a = "a";
            IIG.PasswordHashingUtils.PasswordHasher.Init(null, 0);
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("Adler32CheckSum", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal = Adler32CheckSumMethod.Invoke(null, new object[]{a, null, null});
            Assert.Equal("01000000", Adler32CheckSumVal);

        }
        [Fact]
        public void PasswordHasher_Adler32CheckSum_Compare_True_Case2()
        {
            var a = "a";
            IIG.PasswordHashingUtils.PasswordHasher.Init(null, 0);
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("Adler32CheckSum", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal1 = Adler32CheckSumMethod.Invoke(null, new object[]{a, null, null});
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{a, 1, 0});
            Assert.Equal(Adler32CheckSumVal1, Adler32CheckSumVal2);

        }
        [Fact]
        public void PasswordHasher_Adler32CheckSum_CompareDifferent_True()
        {
            var a = "a";
            var b = "abc";
            IIG.PasswordHashingUtils.PasswordHasher.Init(null, 0);
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("Adler32CheckSum", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal1 = Adler32CheckSumMethod.Invoke(null, new object[]{a, null, null});
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{b, 1, 0});
            Assert.NotEqual(Adler32CheckSumVal1, Adler32CheckSumVal2);
        }
        [Fact]
        public void PasswordHasher_Adler32CheckSum_CompareLetterA_True()
        {
            var a = "a";
            var french_a = "à";
            IIG.PasswordHashingUtils.PasswordHasher.Init(null, 0);
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("Adler32CheckSum", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal1 = Adler32CheckSumMethod.Invoke(null, new object[]{a, null, null});
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{french_a, 1, 0});
            Assert.NotEqual(Adler32CheckSumVal1, Adler32CheckSumVal2);
        }
        [Fact]
        public void PasswordHasher_Adler32CheckSum_Compare_True_Case3()
        {
            var a = "a";
            IIG.PasswordHashingUtils.PasswordHasher.Init(a, 1);
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("Adler32CheckSum", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal1 = Adler32CheckSumMethod.Invoke(null, new object[]{a, 10, 0});
            IIG.PasswordHashingUtils.PasswordHasher.Init(a, 4);
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{a, 1, 0});
            Assert.Equal(Adler32CheckSumVal1, Adler32CheckSumVal2);
        }
        [Fact]
        public void PasswordHasher_Adler32CheckSum_True3()
        {

            var a = "a";
            Type type = typeof(IIG.PasswordHashingUtils.PasswordHasher);
            var Adler32CheckSumMethod = type.GetMethod("Adler32CheckSum", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var Adler32CheckSumVal1 = Adler32CheckSumMethod.Invoke(null, new object[]{a, 10, 0});
            IIG.PasswordHashingUtils.PasswordHasher.Init(a, 4);
            var Adler32CheckSumVal2 = Adler32CheckSumMethod.Invoke(null, new object[]{a, 1, 0});
            Assert.Equal(Adler32CheckSumVal1, Adler32CheckSumVal2);
        }
    }
}
