-- Test vectors of cipher.aes, from the documents of the standards:
--
--   FIPS197  FIPS PUB 197, Advanced Encryption Standard (AES), 2001, Appendix C
--            (example vectors of AES-128, AES-192, AES-256)
--   SP80038A NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation, 2001,
--            Appendix F (ECB, CBC, CFB8, CFB128, OFB, CTR; the encryption examples, the
--            decryption examples are the same data)
--   GCM      D. McGrew, J. Viega, The Galois/Counter Mode of Operation (GCM), revised
--            2005, Appendix B (test cases 1 to 18), the test vectors of NIST SP 800-38D
--
-- All values are hexadecimal strings.

local vectors = {}

vectors.FIPS197 = {
    { key = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "00112233445566778899aabbccddeeff",
      ciphertext = "69c4e0d86a7b0430d8cdb78070b4c55a" },
    { key = "000102030405060708090a0b0c0d0e0f1011121314151617",
      plaintext  = "00112233445566778899aabbccddeeff",
      ciphertext = "dda97ca4864cdfe06eaf70a0ec0d7191" },
    { key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      plaintext  = "00112233445566778899aabbccddeeff",
      ciphertext = "8ea2b7ca516745bfeafc49904b496089" },
}

-- mode: the name of the mode in cipher.aes; iv: for CTR the initial counter block
vectors.SP80038A = {
    { name = "ECB-AES128", mode = "ecb",
      key = "2b7e151628aed2a6abf7158809cf4f3c",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                   .. "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4" },
    { name = "ECB-AES192", mode = "ecb",
      key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
                   .. "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e" },
    { name = "ECB-AES256", mode = "ecb",
      key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
                   .. "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7" },
    { name = "CBC-AES128", mode = "cbc",
      key = "2b7e151628aed2a6abf7158809cf4f3c",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
                   .. "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7" },
    { name = "CBC-AES192", mode = "cbc",
      key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a"
                   .. "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd" },
    { name = "CBC-AES256", mode = "cbc",
      key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
                   .. "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b" },
    { name = "CFB8-AES128", mode = "cfb8",
      key = "2b7e151628aed2a6abf7158809cf4f3c",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d",
      ciphertext = "3b79424c9c0dd436bace9e0ed4586a4f32b9" },
    { name = "CFB8-AES192", mode = "cfb8",
      key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d",
      ciphertext = "cda2521ef0a905ca44cd057cbf0d47a0678a" },
    { name = "CFB8-AES256", mode = "cfb8",
      key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d",
      ciphertext = "dc1f1a8520a64db55fcc8ac554844e889700" },
    { name = "CFB128-AES128", mode = "cfb",
      key = "2b7e151628aed2a6abf7158809cf4f3c",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
                   .. "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6" },
    { name = "CFB128-AES192", mode = "cfb",
      key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a"
                   .. "2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff" },
    { name = "CFB128-AES256", mode = "cfb",
      key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407b"
                   .. "df10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471" },
    { name = "OFB-AES128", mode = "ofb",
      key = "2b7e151628aed2a6abf7158809cf4f3c",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
                   .. "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e" },
    { name = "OFB-AES192", mode = "ofb",
      key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c1100401"
                   .. "8d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a" },
    { name = "OFB-AES256", mode = "ofb",
      key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      iv  = "000102030405060708090a0b0c0d0e0f",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d"
                   .. "71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484" },
    { name = "CTR-AES128", mode = "ctr",
      key = "2b7e151628aed2a6abf7158809cf4f3c",
      iv  = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
                   .. "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee" },
    { name = "CTR-AES192", mode = "ctr",
      key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      iv  = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94"
                   .. "1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050" },
    { name = "CTR-AES256", mode = "ctr",
      key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      iv  = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      plaintext  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   .. "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      ciphertext = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
                   .. "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6" },
}

vectors.GCM = {
    { case = 1,
      key = "00000000000000000000000000000000",
      iv  = "000000000000000000000000",
      aad = "",
      plaintext  = "",
      ciphertext = "",
      tag = "58e2fccefa7e3061367f1d57a4e7455a" },
    { case = 2,
      key = "00000000000000000000000000000000",
      iv  = "000000000000000000000000",
      aad = "",
      plaintext  = "00000000000000000000000000000000",
      ciphertext = "0388dace60b6a392f328c2b971b2fe78",
      tag = "ab6e47d42cec13bdf53a67b21257bddf" },
    { case = 3,
      key = "feffe9928665731c6d6a8f9467308308",
      iv  = "cafebabefacedbaddecaf888",
      aad = "",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
      ciphertext = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                   .. "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
      tag = "4d5c2af327cd64a62cf35abd2ba6fab4" },
    { case = 4,
      key = "feffe9928665731c6d6a8f9467308308",
      iv  = "cafebabefacedbaddecaf888",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                   .. "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
      tag = "5bc94fbc3221a5db94fae95ae7121a47" },
    { case = 5,
      key = "feffe9928665731c6d6a8f9467308308",
      iv  = "cafebabefacedbad",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
                   .. "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
      tag = "3612d2e79e3b0785561be14aaca2fccb" },
    { case = 6,
      key = "feffe9928665731c6d6a8f9467308308",
      iv  = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
            .. "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
                   .. "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
      tag = "619cc5aefffe0bfa462af43c1699d050" },
    { case = 7,
      key = "000000000000000000000000000000000000000000000000",
      iv  = "000000000000000000000000",
      aad = "",
      plaintext  = "",
      ciphertext = "",
      tag = "cd33b28ac773f74ba00ed1f312572435" },
    { case = 8,
      key = "000000000000000000000000000000000000000000000000",
      iv  = "000000000000000000000000",
      aad = "",
      plaintext  = "00000000000000000000000000000000",
      ciphertext = "98e7247c07f0fe411c267e4384b0f600",
      tag = "2ff58d80033927ab8ef4d4587514f0fb" },
    { case = 9,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
      iv  = "cafebabefacedbaddecaf888",
      aad = "",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
      ciphertext = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c"
                   .. "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
      tag = "9924a7c8587336bfb118024db8674a14" },
    { case = 10,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
      iv  = "cafebabefacedbaddecaf888",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c"
                   .. "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
      tag = "2519498e80f1478f37ba55bd6d27618c" },
    { case = 11,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
      iv  = "cafebabefacedbad",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057"
                   .. "fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
      tag = "65dcc57fcf623a24094fcca40d3533f8" },
    { case = 12,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
      iv  = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
            .. "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e45"
                   .. "81e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
      tag = "dcf566ff291c25bbb8568fc3d376a6d9" },
    { case = 13,
      key = "0000000000000000000000000000000000000000000000000000000000000000",
      iv  = "000000000000000000000000",
      aad = "",
      plaintext  = "",
      ciphertext = "",
      tag = "530f8afbc74536b9a963b4f1c4cb738b" },
    { case = 14,
      key = "0000000000000000000000000000000000000000000000000000000000000000",
      iv  = "000000000000000000000000",
      aad = "",
      plaintext  = "00000000000000000000000000000000",
      ciphertext = "cea7403d4d606b6e074ec5d3baf39d18",
      tag = "d0d1c8a799996bf0265b98b5d48ab919" },
    { case = 15,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
      iv  = "cafebabefacedbaddecaf888",
      aad = "",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
      ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                   .. "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
      tag = "b094dac5d93471bdec1a502270e3cc6c" },
    { case = 16,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
      iv  = "cafebabefacedbaddecaf888",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                   .. "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
      tag = "76fc6ece0f4e1768cddf8853bb2d551b" },
    { case = 17,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
      iv  = "cafebabefacedbad",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
                   .. "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
      tag = "3a337dbf46a792c45e454913fe2ea8f2" },
    { case = 18,
      key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
      iv  = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
            .. "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
      aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      plaintext  = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ciphertext = "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
                   .. "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
      tag = "a44a8266ee1c8eb0c8b5d4cf5ae9f19a" },
}

return vectors
