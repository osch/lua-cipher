-- Test vectors of cipher.des, from the documents of the standards and NIST's
-- Cryptographic Algorithm Validation Program (CAVP):
--
--   KAT      NIST SP 800-20, Modes of Operation Validation System for the Triple Data
--            Encryption Algorithm (TMOVS), 1999: the known answer tests of DES in ECB
--            mode (keying option 3 of TDEA, K1 = K2 = K3, which is single DES), as
--            published by CAVP in KAT_TDES.zip (TECBvartext.rsp, TECBinvperm.rsp,
--            TECBvarkey.rsp, TECBpermop.rsp, TECBsubtab.rsp): the variable plaintext,
--            inverse permutation, variable key, permutation operation and substitution
--            table tests, the [ENCRYPT] sections ({ key, plaintext, ciphertext }; the
--            [DECRYPT] sections are the same values)
--   MMT      CAVP tdesmmt.zip, the TDEA multi-block message tests for ECB, CBC, CFB64,
--            CFB8 and OFB with two keys (TxxxMMT2.rsp: K1, K2, K3 = K1, here as a 16 byte
--            key) and three keys (TxxxMMT3.rsp, 24 byte keys), [ENCRYPT] and [DECRYPT]
--   FIPS81   FIPS PUB 81, DES Modes of Operation, 1980, Appendix B: the examples with
--            the key 0123456789abcdef and the plaintext "Now is the time for all "
--            (cfb8: the example of 8 bit CFB, "Now is the")
--   SP80067  NIST SP 800-67 Rev. 1, Recommendation for the Triple Data Encryption
--            Algorithm (TDEA) Block Cipher, 2012, Appendix B: the example of TDEA with
--            three keys in ECB mode
--
-- All values are hexadecimal strings.

local vectors = {}

vectors.KAT = {
    vartext = {   -- variable plaintext known answer test, 64 vectors
        { "0101010101010101", "8000000000000000", "95f8a5e5dd31d900" },
        { "0101010101010101", "4000000000000000", "dd7f121ca5015619" },
        { "0101010101010101", "2000000000000000", "2e8653104f3834ea" },
        { "0101010101010101", "1000000000000000", "4bd388ff6cd81d4f" },
        { "0101010101010101", "0800000000000000", "20b9e767b2fb1456" },
        { "0101010101010101", "0400000000000000", "55579380d77138ef" },
        { "0101010101010101", "0200000000000000", "6cc5defaaf04512f" },
        { "0101010101010101", "0100000000000000", "0d9f279ba5d87260" },
        { "0101010101010101", "0080000000000000", "d9031b0271bd5a0a" },
        { "0101010101010101", "0040000000000000", "424250b37c3dd951" },
        { "0101010101010101", "0020000000000000", "b8061b7ecd9a21e5" },
        { "0101010101010101", "0010000000000000", "f15d0f286b65bd28" },
        { "0101010101010101", "0008000000000000", "add0cc8d6e5deba1" },
        { "0101010101010101", "0004000000000000", "e6d5f82752ad63d1" },
        { "0101010101010101", "0002000000000000", "ecbfe3bd3f591a5e" },
        { "0101010101010101", "0001000000000000", "f356834379d165cd" },
        { "0101010101010101", "0000800000000000", "2b9f982f20037fa9" },
        { "0101010101010101", "0000400000000000", "889de068a16f0be6" },
        { "0101010101010101", "0000200000000000", "e19e275d846a1298" },
        { "0101010101010101", "0000100000000000", "329a8ed523d71aec" },
        { "0101010101010101", "0000080000000000", "e7fce22557d23c97" },
        { "0101010101010101", "0000040000000000", "12a9f5817ff2d65d" },
        { "0101010101010101", "0000020000000000", "a484c3ad38dc9c19" },
        { "0101010101010101", "0000010000000000", "fbe00a8a1ef8ad72" },
        { "0101010101010101", "0000008000000000", "750d079407521363" },
        { "0101010101010101", "0000004000000000", "64feed9c724c2faf" },
        { "0101010101010101", "0000002000000000", "f02b263b328e2b60" },
        { "0101010101010101", "0000001000000000", "9d64555a9a10b852" },
        { "0101010101010101", "0000000800000000", "d106ff0bed5255d7" },
        { "0101010101010101", "0000000400000000", "e1652c6b138c64a5" },
        { "0101010101010101", "0000000200000000", "e428581186ec8f46" },
        { "0101010101010101", "0000000100000000", "aeb5f5ede22d1a36" },
        { "0101010101010101", "0000000080000000", "e943d7568aec0c5c" },
        { "0101010101010101", "0000000040000000", "df98c8276f54b04b" },
        { "0101010101010101", "0000000020000000", "b160e4680f6c696f" },
        { "0101010101010101", "0000000010000000", "fa0752b07d9c4ab8" },
        { "0101010101010101", "0000000008000000", "ca3a2b036dbc8502" },
        { "0101010101010101", "0000000004000000", "5e0905517bb59bcf" },
        { "0101010101010101", "0000000002000000", "814eeb3b91d90726" },
        { "0101010101010101", "0000000001000000", "4d49db1532919c9f" },
        { "0101010101010101", "0000000000800000", "25eb5fc3f8cf0621" },
        { "0101010101010101", "0000000000400000", "ab6a20c0620d1c6f" },
        { "0101010101010101", "0000000000200000", "79e90dbc98f92cca" },
        { "0101010101010101", "0000000000100000", "866ecedd8072bb0e" },
        { "0101010101010101", "0000000000080000", "8b54536f2f3e64a8" },
        { "0101010101010101", "0000000000040000", "ea51d3975595b86b" },
        { "0101010101010101", "0000000000020000", "caffc6ac4542de31" },
        { "0101010101010101", "0000000000010000", "8dd45a2ddf90796c" },
        { "0101010101010101", "0000000000008000", "1029d55e880ec2d0" },
        { "0101010101010101", "0000000000004000", "5d86cb23639dbea9" },
        { "0101010101010101", "0000000000002000", "1d1ca853ae7c0c5f" },
        { "0101010101010101", "0000000000001000", "ce332329248f3228" },
        { "0101010101010101", "0000000000000800", "8405d1abe24fb942" },
        { "0101010101010101", "0000000000000400", "e643d78090ca4207" },
        { "0101010101010101", "0000000000000200", "48221b9937748a23" },
        { "0101010101010101", "0000000000000100", "dd7c0bbd61fafd54" },
        { "0101010101010101", "0000000000000080", "2fbc291a570db5c4" },
        { "0101010101010101", "0000000000000040", "e07c30d7e4e26e12" },
        { "0101010101010101", "0000000000000020", "0953e2258e8e90a1" },
        { "0101010101010101", "0000000000000010", "5b711bc4ceebf2ee" },
        { "0101010101010101", "0000000000000008", "cc083f1e6d9e85f6" },
        { "0101010101010101", "0000000000000004", "d2fd8867d50d2dfe" },
        { "0101010101010101", "0000000000000002", "06e7ea22ce92708f" },
        { "0101010101010101", "0000000000000001", "166b40b44aba4bd6" },
    },
    invperm = {   -- inverse permutation known answer test, 64 vectors
        { "0101010101010101", "95f8a5e5dd31d900", "8000000000000000" },
        { "0101010101010101", "dd7f121ca5015619", "4000000000000000" },
        { "0101010101010101", "2e8653104f3834ea", "2000000000000000" },
        { "0101010101010101", "4bd388ff6cd81d4f", "1000000000000000" },
        { "0101010101010101", "20b9e767b2fb1456", "0800000000000000" },
        { "0101010101010101", "55579380d77138ef", "0400000000000000" },
        { "0101010101010101", "6cc5defaaf04512f", "0200000000000000" },
        { "0101010101010101", "0d9f279ba5d87260", "0100000000000000" },
        { "0101010101010101", "d9031b0271bd5a0a", "0080000000000000" },
        { "0101010101010101", "424250b37c3dd951", "0040000000000000" },
        { "0101010101010101", "b8061b7ecd9a21e5", "0020000000000000" },
        { "0101010101010101", "f15d0f286b65bd28", "0010000000000000" },
        { "0101010101010101", "add0cc8d6e5deba1", "0008000000000000" },
        { "0101010101010101", "e6d5f82752ad63d1", "0004000000000000" },
        { "0101010101010101", "ecbfe3bd3f591a5e", "0002000000000000" },
        { "0101010101010101", "f356834379d165cd", "0001000000000000" },
        { "0101010101010101", "2b9f982f20037fa9", "0000800000000000" },
        { "0101010101010101", "889de068a16f0be6", "0000400000000000" },
        { "0101010101010101", "e19e275d846a1298", "0000200000000000" },
        { "0101010101010101", "329a8ed523d71aec", "0000100000000000" },
        { "0101010101010101", "e7fce22557d23c97", "0000080000000000" },
        { "0101010101010101", "12a9f5817ff2d65d", "0000040000000000" },
        { "0101010101010101", "a484c3ad38dc9c19", "0000020000000000" },
        { "0101010101010101", "fbe00a8a1ef8ad72", "0000010000000000" },
        { "0101010101010101", "750d079407521363", "0000008000000000" },
        { "0101010101010101", "64feed9c724c2faf", "0000004000000000" },
        { "0101010101010101", "f02b263b328e2b60", "0000002000000000" },
        { "0101010101010101", "9d64555a9a10b852", "0000001000000000" },
        { "0101010101010101", "d106ff0bed5255d7", "0000000800000000" },
        { "0101010101010101", "e1652c6b138c64a5", "0000000400000000" },
        { "0101010101010101", "e428581186ec8f46", "0000000200000000" },
        { "0101010101010101", "aeb5f5ede22d1a36", "0000000100000000" },
        { "0101010101010101", "e943d7568aec0c5c", "0000000080000000" },
        { "0101010101010101", "df98c8276f54b04b", "0000000040000000" },
        { "0101010101010101", "b160e4680f6c696f", "0000000020000000" },
        { "0101010101010101", "fa0752b07d9c4ab8", "0000000010000000" },
        { "0101010101010101", "ca3a2b036dbc8502", "0000000008000000" },
        { "0101010101010101", "5e0905517bb59bcf", "0000000004000000" },
        { "0101010101010101", "814eeb3b91d90726", "0000000002000000" },
        { "0101010101010101", "4d49db1532919c9f", "0000000001000000" },
        { "0101010101010101", "25eb5fc3f8cf0621", "0000000000800000" },
        { "0101010101010101", "ab6a20c0620d1c6f", "0000000000400000" },
        { "0101010101010101", "79e90dbc98f92cca", "0000000000200000" },
        { "0101010101010101", "866ecedd8072bb0e", "0000000000100000" },
        { "0101010101010101", "8b54536f2f3e64a8", "0000000000080000" },
        { "0101010101010101", "ea51d3975595b86b", "0000000000040000" },
        { "0101010101010101", "caffc6ac4542de31", "0000000000020000" },
        { "0101010101010101", "8dd45a2ddf90796c", "0000000000010000" },
        { "0101010101010101", "1029d55e880ec2d0", "0000000000008000" },
        { "0101010101010101", "5d86cb23639dbea9", "0000000000004000" },
        { "0101010101010101", "1d1ca853ae7c0c5f", "0000000000002000" },
        { "0101010101010101", "ce332329248f3228", "0000000000001000" },
        { "0101010101010101", "8405d1abe24fb942", "0000000000000800" },
        { "0101010101010101", "e643d78090ca4207", "0000000000000400" },
        { "0101010101010101", "48221b9937748a23", "0000000000000200" },
        { "0101010101010101", "dd7c0bbd61fafd54", "0000000000000100" },
        { "0101010101010101", "2fbc291a570db5c4", "0000000000000080" },
        { "0101010101010101", "e07c30d7e4e26e12", "0000000000000040" },
        { "0101010101010101", "0953e2258e8e90a1", "0000000000000020" },
        { "0101010101010101", "5b711bc4ceebf2ee", "0000000000000010" },
        { "0101010101010101", "cc083f1e6d9e85f6", "0000000000000008" },
        { "0101010101010101", "d2fd8867d50d2dfe", "0000000000000004" },
        { "0101010101010101", "06e7ea22ce92708f", "0000000000000002" },
        { "0101010101010101", "166b40b44aba4bd6", "0000000000000001" },
    },
    varkey = {   -- variable key known answer test, 56 vectors
        { "8001010101010101", "0000000000000000", "95a8d72813daa94d" },
        { "4001010101010101", "0000000000000000", "0eec1487dd8c26d5" },
        { "2001010101010101", "0000000000000000", "7ad16ffb79c45926" },
        { "1001010101010101", "0000000000000000", "d3746294ca6a6cf3" },
        { "0801010101010101", "0000000000000000", "809f5f873c1fd761" },
        { "0401010101010101", "0000000000000000", "c02faffec989d1fc" },
        { "0201010101010101", "0000000000000000", "4615aa1d33e72f10" },
        { "0180010101010101", "0000000000000000", "2055123350c00858" },
        { "0140010101010101", "0000000000000000", "df3b99d6577397c8" },
        { "0120010101010101", "0000000000000000", "31fe17369b5288c9" },
        { "0110010101010101", "0000000000000000", "dfdd3cc64dae1642" },
        { "0108010101010101", "0000000000000000", "178c83ce2b399d94" },
        { "0104010101010101", "0000000000000000", "50f636324a9b7f80" },
        { "0102010101010101", "0000000000000000", "a8468ee3bc18f06d" },
        { "0101800101010101", "0000000000000000", "a2dc9e92fd3cde92" },
        { "0101400101010101", "0000000000000000", "cac09f797d031287" },
        { "0101200101010101", "0000000000000000", "90ba680b22aeb525" },
        { "0101100101010101", "0000000000000000", "ce7a24f350e280b6" },
        { "0101080101010101", "0000000000000000", "882bff0aa01a0b87" },
        { "0101040101010101", "0000000000000000", "25610288924511c2" },
        { "0101020101010101", "0000000000000000", "c71516c29c75d170" },
        { "0101018001010101", "0000000000000000", "5199c29a52c9f059" },
        { "0101014001010101", "0000000000000000", "c22f0a294a71f29f" },
        { "0101012001010101", "0000000000000000", "ee371483714c02ea" },
        { "0101011001010101", "0000000000000000", "a81fbd448f9e522f" },
        { "0101010801010101", "0000000000000000", "4f644c92e192dfed" },
        { "0101010401010101", "0000000000000000", "1afa9a66a6df92ae" },
        { "0101010201010101", "0000000000000000", "b3c1cc715cb879d8" },
        { "0101010180010101", "0000000000000000", "19d032e64ab0bd8b" },
        { "0101010140010101", "0000000000000000", "3cfaa7a7dc8720dc" },
        { "0101010120010101", "0000000000000000", "b7265f7f447ac6f3" },
        { "0101010110010101", "0000000000000000", "9db73b3c0d163f54" },
        { "0101010108010101", "0000000000000000", "8181b65babf4a975" },
        { "0101010104010101", "0000000000000000", "93c9b64042eaa240" },
        { "0101010102010101", "0000000000000000", "5570530829705592" },
        { "0101010101800101", "0000000000000000", "8638809e878787a0" },
        { "0101010101400101", "0000000000000000", "41b9a79af79ac208" },
        { "0101010101200101", "0000000000000000", "7a9be42f2009a892" },
        { "0101010101100101", "0000000000000000", "29038d56ba6d2745" },
        { "0101010101080101", "0000000000000000", "5495c6abf1e5df51" },
        { "0101010101040101", "0000000000000000", "ae13dbd561488933" },
        { "0101010101020101", "0000000000000000", "024d1ffa8904e389" },
        { "0101010101018001", "0000000000000000", "d1399712f99bf02e" },
        { "0101010101014001", "0000000000000000", "14c1d7c1cffec79e" },
        { "0101010101012001", "0000000000000000", "1de5279dae3bed6f" },
        { "0101010101011001", "0000000000000000", "e941a33f85501303" },
        { "0101010101010801", "0000000000000000", "da99dbbc9a03f379" },
        { "0101010101010401", "0000000000000000", "b7fc92f91d8e92e9" },
        { "0101010101010201", "0000000000000000", "ae8e5caa3ca04e85" },
        { "0101010101010180", "0000000000000000", "9cc62df43b6eed74" },
        { "0101010101010140", "0000000000000000", "d863dbb5c59a91a0" },
        { "0101010101010120", "0000000000000000", "a1ab2190545b91d7" },
        { "0101010101010110", "0000000000000000", "0875041e64c570f7" },
        { "0101010101010108", "0000000000000000", "5a594528bebef1cc" },
        { "0101010101010104", "0000000000000000", "fcdb3291de21f0c0" },
        { "0101010101010102", "0000000000000000", "869efd7f9f265a09" },
    },
    permop = {   -- permutation operation known answer test, 32 vectors
        { "1046913489980131", "0000000000000000", "88d55e54f54c97b4" },
        { "1007103489988020", "0000000000000000", "0c0cc00c83ea48fd" },
        { "10071034c8980120", "0000000000000000", "83bc8ef3a6570183" },
        { "1046103489988020", "0000000000000000", "df725dcad94ea2e9" },
        { "1086911519190101", "0000000000000000", "e652b53b550be8b0" },
        { "1086911519580101", "0000000000000000", "af527120c485cbb0" },
        { "5107b01519580101", "0000000000000000", "0f04ce393db926d5" },
        { "1007b01519190101", "0000000000000000", "c9f00ffc74079067" },
        { "3107915498080101", "0000000000000000", "7cfd82a593252b4e" },
        { "3107919498080101", "0000000000000000", "cb49a2f9e91363e3" },
        { "10079115b9080140", "0000000000000000", "00b588be70d23f56" },
        { "3107911598080140", "0000000000000000", "406a9a6ab43399ae" },
        { "1007d01589980101", "0000000000000000", "6cb773611dca9ada" },
        { "9107911589980101", "0000000000000000", "67fd21c17dbb5d70" },
        { "9107d01589190101", "0000000000000000", "9592cb4110430787" },
        { "1007d01598980120", "0000000000000000", "a6b7ff68a318ddd3" },
        { "1007940498190101", "0000000000000000", "4d102196c914ca16" },
        { "0107910491190401", "0000000000000000", "2dfa9f4573594965" },
        { "0107910491190101", "0000000000000000", "b46604816c0e0774" },
        { "0107940491190401", "0000000000000000", "6e7e6221a4f34e87" },
        { "19079210981a0101", "0000000000000000", "aa85e74643233199" },
        { "1007911998190801", "0000000000000000", "2e5a19db4d1962d6" },
        { "10079119981a0801", "0000000000000000", "23a866a809d30894" },
        { "1007921098190101", "0000000000000000", "d812d961f017d320" },
        { "100791159819010b", "0000000000000000", "055605816e58608f" },
        { "1004801598190101", "0000000000000000", "abd88e8b1b7716f1" },
        { "1004801598190102", "0000000000000000", "537ac95be69da1e1" },
        { "1004801598190108", "0000000000000000", "aed0f6ae3c25cdd8" },
        { "1002911598100104", "0000000000000000", "b3e35a5ee53e7b8d" },
        { "1002911598190104", "0000000000000000", "61c79c71921a2ef8" },
        { "1002911598100201", "0000000000000000", "e2f5728f0995013c" },
        { "1002911698100101", "0000000000000000", "1aeac39a61f0a464" },
    },
    subtab = {   -- substitution table known answer test, 19 vectors
        { "7ca110454a1a6e57", "01a1d6d039776742", "690f5b0d9a26939b" },
        { "0131d9619dc1376e", "5cd54ca83def57da", "7a389d10354bd271" },
        { "07a1133e4a0b2686", "0248d43806f67172", "868ebb51cab4599a" },
        { "3849674c2602319e", "51454b582ddf440a", "7178876e01f19b2a" },
        { "04b915ba43feb5b6", "42fd443059577fa2", "af37fb421f8c4095" },
        { "0113b970fd34f2ce", "059b5e0851cf143a", "86a560f10ec6d85b" },
        { "0170f175468fb5e6", "0756d8e0774761d2", "0cd3da020021dc09" },
        { "43297fad38e373fe", "762514b829bf486a", "ea676b2cb7db2b7a" },
        { "07a7137045da2a16", "3bdd119049372802", "dfd64a815caf1a0f" },
        { "04689104c2fd3b2f", "26955f6835af609a", "5c513c9c4886c088" },
        { "37d06bb516cb7546", "164d5e404f275232", "0a2aeeae3ff4ab77" },
        { "1f08260d1ac2465e", "6b056e18759f5cca", "ef1bf03e5dfa575a" },
        { "584023641aba6176", "004bd6ef09176062", "88bf0db6d70dee56" },
        { "025816164629b007", "480d39006ee762f2", "a1f9915541020b56" },
        { "49793ebc79b3258f", "437540c8698f3cfa", "6fbf1cafcffd0556" },
        { "4fb05e1515ab73a7", "072d43a077075292", "2f22e49bab7ca1ac" },
        { "49e95d6d4ca229bf", "02fe55778117f12a", "5a6b612cc26cce4a" },
        { "018310dc409b26d6", "1d9d5c5018f728c2", "5f4c038ed12b2e41" },
        { "1c587f1c13924fef", "305532286d6f295a", "63fac0d034d9f793" },
    },
}

-- mode: the mode in cipher.des; decrypt: true for the [DECRYPT] sections
vectors.MMT = {
    -- TECBMMT2.rsp
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "151f10383d6d199b4a763bd54a46a445",
      plaintext  = "d8da89298878ed7d",
      ciphertext = "89321ba75ba545db",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "e3e93bd05b0b796779491ff8bf1fd65e",
      plaintext  = "d3fa3571b85c4781e7c1a7e61c6ff997",
      ciphertext = "a89a367d0158dc22899cc2a3b5542515",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "cd3d9bf72f8c8ab5fee67334311ca462",
      plaintext  = "2f2a361c8e145dc0a74a1bdb7ca929c338144d89135b50a7",
      ciphertext = "7f1fd32b3690054bfa1b17351579338099ffa84fea168c6b",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "135e26347f377cc7641abc454a8c4068",
      plaintext  = "ad817a4248b4642f57a4473fa2c5fbb3125fedcce5b388983c5eb27842e3777b",
      ciphertext = "c1d09d7c7d52368df140cde3dfe3d72d0b86c32ff72adc14f17b70064f0232fd",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "52bffda2cb70cebaa8fdc40d8a7925a8",
      plaintext  = "5d9548a32b9874f9bfff4001c9ad3fc851e5c4bae4cab1bae323cdab0acce2e6"
                   .. "da820caceed59abd",
      ciphertext = "8dbfce1f5ef94f4a137b28e70684a8d920aa1d014b7bed042a65e24f07d3c659"
                   .. "0d993028b7929d17",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "1608c24a3eaead3b2fb02c25b683c27f",
      plaintext  = "a7950500511d224f7198c9f5f1b43cb5459a9e2f28c711eb620f82b9c833ea1e"
                   .. "6ee81bf56be208d8a75d9666751e54c3",
      ciphertext = "4b45f67cca2d506e2d9a8c7623ccf57f7ca9e8449662e6121854e6cfe32cf03b"
                   .. "464fe7767179a7c32da3508bca2be0a5",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "51a70152e679040d9e0e07bf6bd9689b",
      plaintext  = "b0b5818fbcdced78ae533929548030c50fb12b361f1a3a8df337cf62c4d8dbf8"
                   .. "13df91f24477cc19bca27f5e066240d7ce075e01ce4b0ecd",
      ciphertext = "7e05ddbcd988da75de29254b7c2cc3b994ff39c85a130782ffeb72aa8d7386aa"
                   .. "12925ccd000299aed46037f1f67f8830e0027738832a1276",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "342c2c682fd6a1f1194643ec7cd99df4",
      plaintext  = "bfaa42d3b26d7f5f1df55a3c8ad1be0799a5209647181c06c1e0c772386fe3b5"
                   .. "310e8268f1974dd1b218bdfdfa7296264756c2fb8329c622a7c4b9ca6ad0cddd",
      ciphertext = "9336e8f1ad6331e1b7f89977cc762bdf760de670c4626d8c9c8fffc8536ba84d"
                   .. "7b0db97ffc8b77dc6707102686edd3c438769f667b719ce8cb422a79ab2b17fc",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "ea9b2cc286578940136b9d8ca44c73d9",
      plaintext  = "c34c50bcbab330e38ce1130224434a69b9a37f59590a8fca4a2ec8ede612e3f4"
                   .. "f7fec79e3d858a4168f253f37c1ae000de5c03066a67e22f815552ce96aa2cee"
                   .. "4c2f9bff71e468e1",
      ciphertext = "447321d2425cfbc71be75ce05db57069b80d737b6a7fc8c4fac7458a29f4d2ee"
                   .. "26c9326e016320ae621c9e787bb08a013b9e726ec4d1a99620809a0a2f535d53"
                   .. "e4c7887ab1d348ce",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "37c2bf5e6d7001e637621f1cbc7a15b6",
      plaintext  = "36110804f487319053a09231dbc094f4ce1cbfeab6edf75db2c70e28822898f5"
                   .. "d89ae729b6b17334dc1da7b72ad4b8eadd51d04fc3ef4d2ed5c62b93f81f2b03"
                   .. "52883f5025ffec2e22748ef589f2ae1c",
      ciphertext = "806a19b2238ec5a99962e7ab9896fc949f77b0b3d271507105d27e3317d02882"
                   .. "81cebb6a2edb931f8e7cb7e7e6abc333ea1f250f8dce8cbd18b19e9d79c7ea51"
                   .. "de5c1d1d838b7894c80281718705f9c3",
    },
    -- TECBMMT3.rsp
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "e97c8313ba265d43254cbf9e8f7c2aa8a754d65e8ae997e3",
      plaintext  = "4656ed81a8bc58a9",
      ciphertext = "426a0ac26586bf6c",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "866d3894b3670efe3754a2e50e767fcd3451fb6889dafeb5",
      plaintext  = "50eaab2a141407c47d716b703650f3a8",
      ciphertext = "b784aff11d715d60185d111a2910ebca",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "02200483ba6df7675dea4073b02a1c5b85025423e5c4a4b5",
      plaintext  = "300ce0178d4d545640243b9db818904ae917195de7bb9ada",
      ciphertext = "8f834b37f7404e5edb32d10b175c28ac6d943b19c2598349",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "2c29202c10797985efc252b3da378a89e9a7f88c98c73b1c",
      plaintext  = "4058771b9c808e6935650f97db27e9e69641fcc5e7bc7fa551a29f0918b669dc",
      ciphertext = "9438d7b8b2057a624a4071de46c986a3393da868a29647041418cb946a51d368",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "c402972020ec0e4a64833dfd5b1a43bf20f73bc70bbf8f08",
      plaintext  = "351cc5e4a8a8b0b0db89deeffcc491eefa1fc4cb45d80ecfd596c8fd6da072eb"
                   .. "214d53d116bc60e0",
      ciphertext = "c850f2b1e1d376b3bd0866d0fd23515c4c9560e93d5e74e74eb2d3d904c7f290"
                   .. "eec9539df3d8c78a",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "6826f891079dda4c0e57d05813629d619789bc684ae96d32",
      plaintext  = "f5ee26021650ef218fa4f44aa5ebc5227d86d3a530f5240d21e54bf68f6a98bf"
                   .. "66898c335bf98f69372ae5e87387df0f",
      ciphertext = "a819e2bc810dd1c6ed4e7e076c5a05c3ceb6db5e2174c2863d052493ca24803d"
                   .. "ce588b4b928b364de7588eb662b58ca6",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "94ec51d0804a1531685e1c6b9babc7080289406e511961da",
      plaintext  = "4ec42ebd1e7dc5f2cfba6067da9fe777fb849d6737ed48f61ebc91354ea5ad99"
                   .. "38e33d4f272973cf7edc77b4407f09cbd66f676a0dd07103",
      ciphertext = "dd6115227a40907c835a98eb22786dd6771909d09c4d9e3ae699cdbd110a82e1"
                   .. "cac4d32fc35a5b3db5ba1ac188cc6339c66334dedeca7e4e",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "04e3f46702913213b00776bf52c78acbfdaba1f8b6d65857",
      plaintext  = "9ec9a69ff369225b750338aa11dbee127fda57e424e1a126365d56d1211cdb3d"
                   .. "295f3dd951302c1f7cf548c7d3469c3b66fc684c168a2423b291c17a60ae320c",
      ciphertext = "8588a792640c215bcb3b93897ed8c5496336cac5a4bd393e9d3567f87045b3a1"
                   .. "4c4bfd3e2c3b5e6ee15cfbbad392ef929531218f4e9a8581f0b5c092fd643ce2",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "b6b0dac8a83861103275d04f467a40b3924c3dc40dbf7c79",
      plaintext  = "8f6e5d5da6dc3a8ef87be347f5467205bb3c004e42be763ad638a032cb0383f8"
                   .. "6c8af1e734ac5a7d4162e51605a2bffa3f83b39a29a1fc17f3c3570471bb5c6d"
                   .. "118e0d180fd5b00a",
      ciphertext = "7be01e909b9d8d33d4ba8d24ee9ac278898dcab3afaf4cdef73c539c996b97a9"
                   .. "68779d2730ac7d0cbf6820ee3dc26ca7158ceb37a0b4956516e0d9618cceffa5"
                   .. "fe836cd553a1778c",
    },
    {
      mode       = "ecb",
      decrypt    = false,
      key        = "a8d9fbecb96467bcbfdf57a11c49c77f0d3ece23cdd0f179",
      plaintext  = "89d667ba5e88f563ad029a7f7887971d20447b5cdbec3d2e62a0885cea1156ca"
                   .. "56e8c0fdab6614dac44729b047edef79d7ba4a5d8bbe21789f92b2dd6a8328db"
                   .. "90f36f7f79fd475902589783727e04e0",
      ciphertext = "c3696e20f335b3f7629be338d870d2795b3075e9b8852c3aaea076977f62a9af"
                   .. "fd8e7568831f1b99404e9ad4d52684217ee27db98510c0994f53a263d10eba9b"
                   .. "a296d0909a5175a9a7637441fd4200cc",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "c173e9945be326732a5ba8510d73683d750e8aa45b2043fb",
      plaintext  = "eafbf94ad6f5be1f",
      ciphertext = "30cc2293138bed53",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "e673fb0e49ea02e6cbb0e098c89d9e0d1a3e6b51cb80e649",
      plaintext  = "4c74545c313ff92381cc2da5979740b1",
      ciphertext = "bfc06e026027a07913026f2dd07e24d6",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "a16ea7fe1ace54cb37f8effeec086eb39e15ec26e068e0b9",
      plaintext  = "c5e2d7125e40cb981e8becd4d2874a147ab2f3e54a03ddc8",
      ciphertext = "63fa2540cb8477b46ce9b9e53e8ad1e88dd38e27ad1df564",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "5b7a769e45a4795132c7f173e5d0b6bcf26dfb89ad8afdae",
      plaintext  = "29d9636fcf01af031e4e1b5ad43c3912f6cfa229278319c9ad4d9df731fd2779",
      ciphertext = "8cbddbe54984d15b17c64691fdc18b5fffbae2cd939f93d954ec3c75facb69d0",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "9d02d05237b66d91a13870755eefc464298652f2f27abf0d",
      plaintext  = "5dd7c7bbb96604731e118abeedd48dff30d2bfa431b3383fcb50f7ff18d35f97"
                   .. "f8e08e08fc98eaba",
      ciphertext = "1e22ea4979b686b2cb5816d80eab0591944ccd7c48055ddd3844bda850cbf4dc"
                   .. "68a82a1282680a56",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "57c846bf26676e6e98138973fd01ba2351e3d38989100eb9",
      plaintext  = "70f2dbad9f3f5180ed19b73b6115147f12e9724bc8086e95dae2d5439cab2eb1"
                   .. "f8d052e28ce9cb0f61a92e9be68d9fbf",
      ciphertext = "e7628ca838cc72cb8fc7c15da087f0c8b86fe233f67aba04b7d9f0a352dea581"
                   .. "0618335a30c009b7c153b6b6f081430d",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "a4eaa738dfc8b07fcbfe1952f1629dfb9867a88fc1a8f1ce",
      plaintext  = "b0ba79d7c2e2314e8f14049379c07fa4c929eaeec0db7413cb3b3d6d3445b2f9"
                   .. "40e47c1457bc5ddc97ed1853b245200c1e1fec3d329ece7f",
      ciphertext = "1bf9bf7f779424ef8c67b173bedb7ed4811d50d36416bebd4f9e923f08ec727c"
                   .. "fc51c05d3d27be28c704f6550733d99d9e64a65362a28df7",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "73a2684a75372008c2f70e23895ef74ca4e313708301d610",
      plaintext  = "fc035310c7b4f1bf9efbd03a6739a27bfe52f80a4f4c1c70964ea12848da014a"
                   .. "5056920bacdd2c95e6d042b26121b9c4ad8bc2654b7d7835a87729ec0a9a2294",
      ciphertext = "fae022317488247505f7ad9b948b7016147a99f5a8690e160a3af4962d25768b"
                   .. "210ac1f6380553f367447633ee1507ac3b437c8f0ca3267bd5eab2f061c1f606",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "bc51a2291af4bc103157269e7a4c15b5a13197d9ad970db9",
      plaintext  = "2edd7f0ff086abd0a1b121d053f7fb0959ba89fdcfb97eb42281fd1885a95cf3"
                   .. "d84ec0b0fe2ebe5550ada949a152476603df9bd09a48d001c9b9dc20d082d1e7"
                   .. "c27385f0cccffec1",
      ciphertext = "5415ca2d2cabe775b817b22b8fe497de96b3c0db73e02ef34462097f90f334a1"
                   .. "7d7225cc4485f486e382b16c1290fb777709ce7f1d239dfd23d0a115b1e270d4"
                   .. "3073d1b6bb84cf6b",
    },
    {
      mode       = "ecb",
      decrypt    = true,
      key        = "b5cd0e1f1f86458f342f2683cd3bbfb91085e38f67c2b9a1",
      plaintext  = "944cb97a226839366dfeaf4680b4adad05372c6f9ca460f687a94cf2864832ff"
                   .. "5d572ef1cf1641a7e0082d6f48285af7e41f1c6b100e67e13793660c34388fbe"
                   .. "f043f0bb87d7aa8ab2cc987790c151cb",
      ciphertext = "bd791aa9d342dc4b7dda97cf0a1f41ab30c352be5c4fc17b4767304aca4f642b"
                   .. "f3aef79d589251beabb5d4b38fff574aaa4bd6defc6e677c6f757043af2f1811"
                   .. "3becfb5cbd83225d979a3274be21e3c8",
    },
    -- TCBCMMT2.rsp
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "bcfe7f25f2b0a72c6276ae1f389d8ae9",
      iv         = "f29d4ba5172fd297",
      plaintext  = "0611a474fb090978",
      ciphertext = "1b3889c9dbe10d03",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "498adf3b0e0e0dce8c917cfd19a83802",
      iv         = "96567ff62c6bfa95",
      plaintext  = "9496469854ae6a74d37e3c2bac780b75",
      ciphertext = "e3b7f198520383b7b4e7fe146d830c85",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "766452495bbf797c0e57d6389b523d3b",
      iv         = "03497624eccc76c7",
      plaintext  = "cb90fca413c884390077084cd866b6c8150f4f5d44c6d622",
      ciphertext = "a835afd4dad376d611be4fc1282d1e3e36b3be081b7c3a4e",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "160b70ad26e60e8a1adadcc240619ec2",
      iv         = "200e89b4097ef967",
      plaintext  = "5ac6533b1de8edd31224a91f7361dc2b4ab33a5db7acee1cc8bfdf82bb1777c6",
      ciphertext = "50e5c5bcc3d84c47fed29ce4caccd5fc7724f56615f8ade5e7d26df2148bc2bc",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "291937806e2f7c52b90e3737049e7301",
      iv         = "e3188bedc5af4d4d",
      plaintext  = "46fb64785371ee25cee35171a6dc8fe95cdd0b73d27adda91d0a8a0c99209328"
                   .. "15a947e193467540",
      ciphertext = "06c3cedd527b120634f96dbb020df802b39f90923aaacff013893ad81b72bcde"
                   .. "a4405455c9750a70",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "fb1fec80b3834fe9c1e3fe1aa2e54697",
      iv         = "f1a61e614197e86a",
      plaintext  = "f8cb81924233608c598820198cce452596c330910547a4e36804d693cb59f074"
                   .. "b935f1947fd0befa86854aec28fca9b5",
      ciphertext = "86e620d24a240296003f3c8d712902e5a51cbd3a5639165ca47051530b9fdda0"
                   .. "91fe29c644bab909e3e07876dc7d5023",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "8a2a3b2546b3adf707b552ab7f25bc7a",
      iv         = "0eb578794b472a69",
      plaintext  = "6251ddd274641e852d93a9f6ed3329ff8eb9720afc1e6727bcf7036cd4d912d2"
                   .. "abf00f8b6e0175e2fc62888fa9ae9bded2426fc3db32bf38",
      ciphertext = "b9417a8e85b9c6d66ffb42da3c4781f2b6d3321eacbe489b3b4559b44c3944db"
                   .. "5eb017f886fc3001b3d9a2cb37eada20836782113210a58d",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "13385e1a86d0013d323dec687c108f5d",
      iv         = "37af5ebe47def2dd",
      plaintext  = "9260811cd1051bd853027c67706be318a5d109afa7b44a3acd83738649c14d1d"
                   .. "acef326ccdfbd9921bbd43f81eae0a605d4a257521eae94c369e00004357d6de",
      ciphertext = "0654b84f30cbb2846bccd9d56463d6db9e12f3465b2322cebf3d416d33369ccb"
                   .. "0828b4fa5cc73f6342f16f001d8777cc4d7c4c780e2ba8609cee55bd9ceca81c",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "6bf857da5ddfa715070779b57f1615bf",
      iv         = "7698969b002a8cf3",
      plaintext  = "6aedae008384f76928347d32a28143b285ae712c4eccea617fb84aabb4332820"
                   .. "4ac41813a365b464fd8fce810fcdeff9a535456543c4d84b2dd78e24368a87e4"
                   .. "c46260b5b9f77031",
      ciphertext = "8d4dc65e0182b339c864a7cb051984803f9ca84f64b3114b0e21c475041d6fd5"
                   .. "04044dc9c04b4a9c26b7685ae4d061e32c938e3fb467073102520c0fe66da3d0"
                   .. "4895836723643150",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "293d0486a2e01c7691ad1aecd5f8234f",
      iv         = "acf2b26a48cc552c",
      plaintext  = "1daa451d2054a48c6c03337f736a63c724784b64034b669c380799b8319457d9"
                   .. "fdae6747efd15b47a5931a15980d97c309658d74d8288874554940e801986620"
                   .. "cfc9ef13e06ef26d938b52965c9e6a72",
      ciphertext = "bd80f44b6047d3577e645393d9636088e7b53ebc25ad7ad6aecf20020c4a2e97"
                   .. "4ec349f85a54afb885d56d01615ad236d6fc23d775dd90a5086667076ed388ad"
                   .. "a6f2197329277a887db47bcf0737cd85",
    },
    -- TCBCMMT3.rsp
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "46133dcbf232b51964e0d95e83208f156732bf75b673abf1",
      iv         = "34814c87f47fd59d",
      plaintext  = "de655a0ea771436c",
      ciphertext = "092368405296744a",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "6d0d67da68ab166d1f43c7204c4c2aa4c81a528515f1dff2",
      iv         = "68e63a07b22e33eb",
      plaintext  = "4346c4e81380626fa0b2776d30a4fc05",
      ciphertext = "5274be183f5dfb6b018f22b322f0392d",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "134cb3efe62a4ad552cb85a164fee6b964a1269b193d68c4",
      iv         = "0fa311f99ec57b86",
      plaintext  = "1b735b0557255a0e6d8d675879e7201ca34c8761a129a914",
      ciphertext = "2f1ac7ee1414af15587cb2c540401294028e1e39d1cf2f67",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "202398b6154968c168201329910e612f296189d320670120",
      iv         = "514273c93806fde6",
      plaintext  = "9a5ec913876299492dda3998f88e1c31a75493b3ade14e9ed7de1f0a303f0299",
      ciphertext = "9bc02247ff5cefde9a0307f948f9437ef2a298cdd69542236cba47e8c954e819",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "199476c24302b6ab0b98d5a807079e4337e68f5ec77561ab",
      iv         = "6e06875955b87f87",
      plaintext  = "420fdffb706770ba1aee85bb992ed2efe7c4cb10a75cc03565dd4da41ee1f1e7"
                   .. "0368fd227acdb0a3",
      ciphertext = "f390d5afc5969d63d9c0a95e1f1c290d0bd29510e8e982502faa7ed616cfe873"
                   .. "af88b27a7b62cb21",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "323bf24fe0ad70943e70bf1c5df4d531dc0d926e83804c4a",
      iv         = "298558d95517a045",
      plaintext  = "26e44aa78fcc690687e74cfdfcbd6ef34696011e5ae1cbfe40d6332bc75b9c51"
                   .. "7724f179c71f818a900f0e0fc276203a",
      ciphertext = "d09b9568877769780fda9911c29b303b27e15b5f29b2ddf89c3b7edcc04dee78"
                   .. "b751d459a50df3ae57bffd4b4ca41fc4",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "f7a494c27326734a104525041052103ef2680e3bd35ea158",
      iv         = "a5fe08d9045bbf88",
      plaintext  = "f9117249047fb9fe884c89267e5ac96314f233d201c14d3315209a4a14991184"
                   .. "c4a6cede45bb0803a18743b4a478c66dee7d5046460f0717",
      ciphertext = "c89ff7bcc5558952e8614a7bfcf8a1b017f040ef954f6552696ae53b70e6f953"
                   .. "ba6d9d0efe381c2bdd54d911ad6eac5b0ce2845341ae3458",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "d3318958c78cfd98c7ae312a2c08bcfefd10269729013de5",
      iv         = "01b6dd4a4c96349a",
      plaintext  = "83577346841a1bbf08fb6d2be351f33914efc8ef9aa7054b890d7c2b5c7da96a"
                   .. "8d60e54c63aadd1c0ca74313ebf8c37c33d93916b5a521baf69b4e3d85e2e098",
      ciphertext = "8be30ca745a06e2f67c3ec2ed18e872028448597218b007746d954da0ba6b3db"
                   .. "20f9a28d7faea32ee3f13103dc8018e8f97dc2c348d2966c9e2b87b0f318e026",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "a4e50d8a1f64f4d9f41a8ad0a8c868b34ac861dc4c38fd89",
      iv         = "f21047a08a1bed96",
      plaintext  = "fa7c94a2eb67dbf0ce8e30d5b944e9585ffef8b9d807cabda0756f46e15bfa26"
                   .. "f5402b3526d04ba2b9d258862c5a62bfbb4035fb29d03813bcc3959b8a6f9ab7"
                   .. "f33a602f6f54aac6",
      ciphertext = "e4025b1f5bcde6eae6c7bbfd4851258af6d097791a02d8df5483a8cbcfeaaf52"
                   .. "dddb61bf1ddc52b9cb6df947cb0492489036212543fab82694449c8d3d323dce"
                   .. "016e2648ac6f653e",
    },
    {
      mode       = "cbc",
      decrypt    = false,
      key        = "08763da862ad16ef5815408f5d3b705415ab1543a42c3efb",
      iv         = "0634d69eaff3ae17",
      plaintext  = "109a3d3d745d65b38edbc73d1de8b2807f7820221a6c3937faab19fcbb75d3c8"
                   .. "aaf4b63f2714cfc94e95ae43d65f6df43815efc214ec66a5d1be185d855a6260"
                   .. "141ffd179bc980490f8a26d8215dd2ab",
      ciphertext = "e9513e8892a09085bee29c358014afd60d7578d21e00a31e5d61b965c18778eb"
                   .. "e18469170794e5ddf24aa777c8ab0a2c62474109e617978bcc5ce3456ddd9622"
                   .. "833420443c2a26b1b6e20a05c189da6c",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "798cc4ea8a1cf8df579e8a70f438b55476b679525bb0d0c1",
      iv         = "77340331c9c8e4f4",
      plaintext  = "f549ecc2ffac9bf1",
      ciphertext = "1addcff67c28da52",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "108ac8f7dc5132bfa26e622cc73e798a2fa8975b58bce910",
      iv         = "7e23c65a97aa017a",
      plaintext  = "f1a9ad10effead21fff6652851efe797",
      ciphertext = "fc54d274304a81fc1654696c87fac6a5",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "13b0465ef83b34325e3d20ab5d8c975ee592297980efc4cd",
      iv         = "28ab21f34c7f1dd1",
      plaintext  = "09051d3e598262006cf44ff7970bb65f8fdc25d48e48866c",
      ciphertext = "59c21b845c4919125d88cfd3ab2992ddd8ff36c0053c765b",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "4c348916ba0ebf54cba807f73d98a801abcb3be98f7f37f1",
      iv         = "06788755657d52a8",
      plaintext  = "d049506c1cb9bccc8b01ca0faed04c495b1b118ac6bec2b7514ce35a4d996897",
      ciphertext = "3421ab4c1f3729cee05eb85dc245945190217495555b6cfe668512dba293e0ce",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "cbda4a4cbcb0fdd6c4c4d0b06be085b092abdc07bcb56ba7",
      iv         = "47626f9fb95ccfcc",
      plaintext  = "c735fc558568759d2054a3b84846a3c27ff297cb477ed91ce1764776e6a37306"
                   .. "1970b87208b9b601",
      ciphertext = "db48b63d6331b747621d73cfd3efd4690b7302ee91e7d71e2fba948a4993d2b2"
                   .. "6e95bb6a2de27982",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "5e75524adc23042c4f40bf80ef31ba5eab70801531c40440",
      iv         = "ce77711132c07898",
      plaintext  = "67d77dd7d34a36b938bbadb6c6f52e67289a36a5f149e62062ab1627b5acea49"
                   .. "62b0bee99c09f716012d243633d016fa",
      ciphertext = "4a00907dcbcf6a554e6782a9be12cb3047625e2b72c5c29b92596bb160028086"
                   .. "e2b9e20c91276945ba7271b22557950f",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "da3e23730768dcd91c914a8976e5624c1f52348080bf7a61",
      iv         = "d3a82ccae468564e",
      plaintext  = "964fb288840d766fbbf01f0f47f6959c21d3224991e0a6e06495d15646551860"
                   .. "38afce17130779726fb99e6c3c44f17b00e9ed21063ea139",
      ciphertext = "ed5c1ca1f3cc828d14f4a496efca35f4e6f3cc2e74d1dd3ec0bde8f07291f08b"
                   .. "c56a2fb3ddac088e5c463d263037620eae519249e53c6067",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "e6686d2a4cbf0bb0015449d561d90bdcdce32f98165b9158",
      iv         = "ecc39d5edd07c642",
      plaintext  = "89708b2b55d09eebb7bd480bf118d73e89e90e15478f93ab05d180eb7a3da16d"
                   .. "3378e2c33043e027416bc25a559fbfe634b31e2a8c0973f319b0e3503ab98eb5",
      ciphertext = "c4b3634b5bc3f395caca1e9971fd4fe23edd188e6917825161a8a1bd06446bc0"
                   .. "18f9ca6eef10ef006d34ea1d32d677590ecf1bfcbc477004cdd6bd6de2eacaaf",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "2ae6ae5d75348f9d34c4fd4585b6ba8c9def6ebfc77fe046",
      iv         = "a52b66c3343859e0",
      plaintext  = "24192642f7c70e7d7569de8b86204a10a076e3f379bc7f8a5225ec4d76c08aca"
                   .. "40cde886f5d99bc0b665a17956372219cd52cb73ec4862df242fb765b1853bc6"
                   .. "258241e41a1ad715",
      ciphertext = "950e26c3f246d7edffbdd30e9a2c082b48533fbf2629a9002335bb636d3c3c62"
                   .. "291c9d7d67f8887f5595bb02b20417358682f4dd119cb89a0197a86ce80efe75"
                   .. "ecdd3b01c13ebec3",
    },
    {
      mode       = "cbc",
      decrypt    = true,
      key        = "b604ec255e04540b230b4acef13840c1e958b9f2e9139d57",
      iv         = "586c471f4ecda1de",
      plaintext  = "900c63a08fd142a9c162639391e0e2b64697b7a516d69cd77796d490148773fc"
                   .. "984f21a0c286d73d86d8fd8011af8f8174e03ead4cafb9641246615aad9ba8b0"
                   .. "2fde3edff35526d3ba21465d2c99f87c",
      ciphertext = "f7c08a2cf5805bc15c157cfffe5b6749426cde2819c37e9334a2976e75b03b50"
                   .. "a3e7958961ad7c64614148a9d559e566260a26efe9e75b240f6d25f25b9f891d"
                   .. "1aed443c0e5a5e05abde02ca86098d44",
    },
    -- TCFB64MMT2.rsp
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "9ee0b59b25865154588551341c4fef9e",
      iv         = "6e37d197376db595",
      plaintext  = "dcd3cf9746d6e42b",
      ciphertext = "63cad52260e0a1cd",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "c179d0fdd073a1910e51f1d5fe70047a",
      iv         = "b956d5426d02b247",
      plaintext  = "32bd529065e26a27643097925e3a726b",
      ciphertext = "896072ab28e5fdfc9e8b3610627bf27a",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "a8084a04495bfb45b3575ee03d732967",
      iv         = "00fd7b4fdb4b3382",
      plaintext  = "c20c7041007a67de7b4355be7406095496923b75dfb98080",
      ciphertext = "9198c138edb037de25d0bcdebe7b9be10ebd7e7ea103edae",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "c1497fdf67cecbab80d543f16d13c8d5",
      iv         = "a1241ca0fe9378cd",
      plaintext  = "157dcfa7ad6758335e561fa7dd7f98dca592e9128e7be30ccd1af7dc5a4536d5",
      ciphertext = "08fcace492f82282fb3255884a64a231dd438069ffbcb432bd7ec446f5b8adfd",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "fd0e3262ec38fe5710389d0779c2fb43",
      iv         = "33c9e4adfb4634ac",
      plaintext  = "37536dda516aab8a992131004134ce48c56fee05261164aae0a88db0f4341061"
                   .. "7f105e20940cf3e9",
      ciphertext = "80e8a96c3fe83857fc738ac7b6639f0d8c28bfa617c56a60fd1b8fbdc36afe9c"
                   .. "e3151e161fa5e3a7",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "ae32253be61040157a7c10b6011fcde3",
      iv         = "47be2286dbccdfe6",
      plaintext  = "e579282129c123c914c700ad8c099b593fe83fdef7be7e5ffb36add9c6b91644"
                   .. "cc79c1e457212017488963e16198c528",
      ciphertext = "7185c5800ca4d5432b50f5b7920e26296c2913e7e3f847a1ef639e156ba4f9ec"
                   .. "6e4b36ded885601d2b9d22f19dc3829f",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "df83498cec83084acb7aaef26e58f1e0",
      iv         = "158d2ca6e70b18f6",
      plaintext  = "4fb7cf2a244ff20beddf8719b2d9c78ab0710703036f804f08bc1f7927ea9906"
                   .. "ba1ef57afd1553c5304c0b72694cd88bb6cb1289772dfff0",
      ciphertext = "158b396cd1969a07042e808d0c875d74166ce77291df233fe300c29c5a30b194"
                   .. "6575ec02042093537dae3f8d51ed96906e601d9da6e34e14",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "ce31cd2067c157199bfb3b8ad9ef9223",
      iv         = "d31741512b6a7471",
      plaintext  = "a0447f5abebf8623db81b600699ce8373353442908fefe8c63f5e29e22ba1057"
                   .. "f759635505ed0ac059887def2d31f6996128d4fbe2df6534429744d7f6496768",
      ciphertext = "b3a791b128f003bc28cd17bbb5c68990faec73f88c10b664f1349b045f3fba24"
                   .. "c5f51bbb10259c41a72492c2377bb331b6dd34fea25c2eea8adc461bd0c78d6b",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "5bbc3423bf67e05262d65740708019f1",
      iv         = "14544ea4813c49d9",
      plaintext  = "a21f26496f74fd8a93aa5423e2a4fc76facbff015db2f4ef14f08b8c13a29d05"
                   .. "61e4e57d04b0b00211f8fba46d025a9c0727c8aebb7d25f27f1606321909ba50"
                   .. "e660fa25358c63f9",
      ciphertext = "c3acc89b9b6037effc65eacdc23b36c38d0e609566d360eba594e4481108983b"
                   .. "4a67a5d9647c776ad5fcc4639116ca95734bd8a3df800fb9a6526a7b29a9fc3c"
                   .. "c29079715f44f865",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "197c738cfb6e0bc2fee57ffb1ca72675",
      iv         = "f1a42447a333caa3",
      plaintext  = "6f914b6996ee8e7ea625b2fddd7677b4384320be0aba3af81d1210965ac37983"
                   .. "f340d5698ddf35d45dfccbf783a50c6eed1a730b5c98675cb6b7645fc8374e10"
                   .. "d8b340c44b0eae988c1ef635fab913da",
      ciphertext = "8aabb83216e4bd5a3dd20586e598bb8e956dcbf7d09cde17a2cf8b7a788ecb85"
                   .. "3503ae5981004dfa644300b115f8d1ae0c7f30f25e70e86c4adc51620fd6c713"
                   .. "01325c9bdc8dca16588eac08fe6aedfd",
    },
    -- TCFB64MMT3.rsp
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "e0d525e9eca226d5584a702fdcd3df238058ad4c1570348f",
      iv         = "8bf6febfde90bd17",
      plaintext  = "2685a38657e8dbfe",
      ciphertext = "e9fbc028105354ed",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "02f1b56451c8207fce70928f1fcde0b36dcda858efe9b06b",
      iv         = "ee346153c09dc873",
      plaintext  = "a72f0d3fb8d4d8f784ce120f2b4b8538",
      ciphertext = "3b6b32365dace6c99b7674fbbea17a9b",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "76dcf7ba769bd3323402c2ae611502c8d5c22615efb0e09e",
      iv         = "5b48334d9f3a67da",
      plaintext  = "b4d0024c7fa140bedea219dcce367aa9d610532782dfa819",
      ciphertext = "26a9836cfac96dfa2e455548d26c09ea93e53bff52375cf0",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "4f5dadfe3443803d07dccb2c3773dcb5c4c2d697cd7f67e9",
      iv         = "9a6d3d65d3ca4dfb",
      plaintext  = "1c1f3ce7927d2562c053c65d738a6ebc92bf599c52a482dba8a3b8da04c5f481",
      ciphertext = "b688dd165b56128c8f14ccd59912631f130f0d95677caec360d49658992e09ec",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "02c16446e5254c9745f1ababd6c7cd9df8cd0d4a0420d3e5",
      iv         = "61542ac607bb267e",
      plaintext  = "f907dd8581651feff33d545dc4b94a74d3d171f5aa773d950112cc09842ec960"
                   .. "d7729095d6d29365",
      ciphertext = "453fe01c94f0d028acb8d83d66cac3734eb843ab4b6cbd6c0cbf1a1e8e554c88"
                   .. "13fa4293a93c6f8c",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "7075571523d902c89b0da20b8570430470e561da58fee038",
      iv         = "86d8a5a076ceae0a",
      plaintext  = "1839c8b6cdd4070adcc4242c484e5e315ddb8f5ce956019ca9d68255027dbb63"
                   .. "f1a0bd5d4527dd160c37c26a4b0fbc37",
      ciphertext = "4fe97bab6c9dddf7f67da8f2c1673c17bf35d74d8cf4a1b16ac1b274f71240ea"
                   .. "ef7931818ba7453a09a74e3a1cb0c481",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "795b8098e5b3e567d9a89d4a8c083e540ef73116626db032",
      iv         = "e192732582bf0085",
      plaintext  = "02bc7eda94e89119a96ef5501d0591963a270acfe372952d114e09f684d03987"
                   .. "b2de809904949dc341e7c1404a88e7f3090b64a8a449bf9d",
      ciphertext = "dd8724cdd953f695109caa068dd71aa658e75e7964c2c6021c771d53590560c0"
                   .. "0c88ccc6ee148e2872a1337037e279eae02760ac0fe48396",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "7c7cc7fe4af20e6b38a8795dabfdba1fbc5d25452a943234",
      iv         = "8432a5462a16bcfb",
      plaintext  = "588a369d93dd68bd518fd341bab48310ea89146af465d37927ec20299086173a"
                   .. "bf106f94ced1a1daa0af4d4167a2daa3696a5ecf037dbd24ee44145ec18658af",
      ciphertext = "2bfb5c7b2d9fbe4a514a2d140caf8c4646fd13d9c251c1073d07f895ea99ec90"
                   .. "f45abbd40bf40fc785aa9f9ff5b925cd29db70e5149c162879ded945a77809c8",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "8c37bc4932016479f197b0f757cb16f14654fb499246daba",
      iv         = "fdee51b06b61fce8",
      plaintext  = "c15507d725afa14755da2cc3cdf59a83ad28bd2005ddaf5e502c71483e96d283"
                   .. "b7f792dc1cb6c823d03f813cf7b3aa737ddd30105a69652b1550a6c287973b09"
                   .. "e2397e01f2623f4c",
      ciphertext = "e56f5d07806061cda9cc7a830964c1647e92023db2b68dd84aa548f486ccc779"
                   .. "d27dfaef171c52c6321f9f47730d2a8e109b67ad5759d56244066769e43c6c11"
                   .. "e905a7372a81456b",
    },
    {
      mode       = "cfb",
      decrypt    = false,
      key        = "4f5226019db36b40464392c8e5c42ad95e2032263dce8f20",
      iv         = "ee24f2e7d6d1f6f9",
      plaintext  = "6a9aafb34b4dd8ad400721b5c2ee625015c89a92cb6d92358b7cbde8104e63e9"
                   .. "7428fed6afb5e5c15bb32782baecba51f968d594b6e19af5c177f8b81fa5d04b"
                   .. "5574561fe3eebbb70ed609ffe2964ede",
      ciphertext = "349ddf37bfa125304f91035aa02b5fd5c49c6fd244379c43cf7ebecad489e38a"
                   .. "edeb7490a77bb1777d628f018c86222ebf4d12483f979ddf136f35151c565c54"
                   .. "f86f2459adc7b1668066e69fc2661701",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "75cbdaeca7979e6b0b45b58568b02938d3c8089ddc52b9e3",
      iv         = "d27ec214f053f985",
      plaintext  = "426f4cdc805227fa",
      ciphertext = "47d37d409ec30cb6",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "9bd0cbef833e542023d0799275f4f2b50bfe5464f143e3f8",
      iv         = "2c130b4c7dbe6954",
      plaintext  = "9ef978f14f7bc66fdf8b603a672404b9",
      ciphertext = "68c84b896c1d6c0c73969900697ec02a",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "6e70ae9e79eac41051a7fb6d85dc23d59b496e5e9e19add9",
      iv         = "487d64093bb7b943",
      plaintext  = "f9362f238d3a28233b4965474a557c93928c5dcf968e6395",
      ciphertext = "d9784b2d2264696ed721e1362b60b35b2b4d631dacba9565",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "dfe0eacd9d79f7797f70f83437805d8f08c18ff73b37585e",
      iv         = "5a409e7d67c54b0d",
      plaintext  = "351ece5d27d15bbc95b59558d08e8fb3bab5b3a2c50e5d88673190146865b955",
      ciphertext = "4dac2b87d7ea180baf7d50d34a14942a1773691361c61c397635042509b807b3",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "b034d5a2a7f7e3c4fdaba1f8b6d658579ec8a79ef268235b",
      iv         = "d74fe16c79f48ae6",
      plaintext  = "208e784f576af41ab001790c6e0ea3eda3fa188c574c80daa5a29066c48229d5"
                   .. "61d157e9b0b827ec",
      ciphertext = "a0f6beb6ceb6df7477538161764df719414b18a514b287aa4c7638e011312fc6"
                   .. "37728b956657c472",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "b94961f1209bfe944508b5c1a4491a5d70430ddc19d00e1a",
      iv         = "14535484092ae9b2",
      plaintext  = "b5c1d5c3fc51a595ab117c7f4f0098a497c4705a6f6cb8a8020edf042fc5159d"
                   .. "844fe83123ab10538be381cbba11a4fb",
      ciphertext = "2f707480c3b0fc554282d709957a5f5e0bf7884a514771409f1239b12ff514d3"
                   .. "f36d9ea187f76f236575efef58d46bf0",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "ab346b0861f2daf7e6ceb5e0a7a23797feb52fdcb002518c",
      iv         = "66263e635b2db78c",
      plaintext  = "b2ccdb9b144b079bd4f678a84416d76c3a6efb03ca899e366b597cdfbe9da0e3"
                   .. "f5300cf6345b2edfbf4382d3b9753b7c4675ea57c6c35882",
      ciphertext = "15ab1b242d1cdfd46ab560ab1374343d764037437c29c5f880f22cc261cc6015"
                   .. "d665f19402213b7a49a7dd3961a06c61acbb68c2c5f56ed5",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "bc32c170bf6e76434670e9cbb307e3f8f25d8643157fcbba",
      iv         = "7e65781727e1e66b",
      plaintext  = "a8182c26508c04d70878c97fe1eb00e393c54c643ab6a9f9e79d57b5700e79c4"
                   .. "c3890d82ff5eeafdf3bd47d150fe56ceaebe7ba67160f81403c279de6adf9eaa",
      ciphertext = "b6e6114e8a6cb0177cf63d3afbffccc5f09faf1551c5a53ff2c04eaf9f05e20f"
                   .. "692c236b3d3b9092bb27dcbf44989e7855ed4ab714806048292be372cf0b0dd9",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "67578f80c7d08c75a226cb08bf791a7c8a2a3b2546b3adf7",
      iv         = "06b553ab7e25bd7a",
      plaintext  = "c7f342985a19cb5ba7c2b7258dc62e28798511fc2efaa05ad104270b80e681fe"
                   .. "8971be0b6902e614671f5dcdd34fcc3a41bc4a12ee867898e3703c2f42abfa62"
                   .. "712a3e8ebb7ce5b7",
      ciphertext = "0eb578794b472a69a9e761c4d8d2715cf8fd905f0ab4e821a481eb1ce94fe736"
                   .. "b9cfda42251b87c8269ac9098e23283e3e65aa219a86ebae3a0a702be2f73966"
                   .. "b536953ea53d3b64",
    },
    {
      mode       = "cfb",
      decrypt    = true,
      key        = "26fe46f775c234b5299ea1da168ce60da1e5515798468fb9",
      iv         = "626c2dfb4e4ed366",
      plaintext  = "0dc2c75e4ddf8bbc3613fa6442d39c2fa031561a5e98ecbf3633c4a94e96b96e"
                   .. "84fd4207e384798b1f953dc263c51f86e66196d5817c3f04b83192e262e16e5b"
                   .. "e9143b81875b9d37cce9bfb0eee026fc",
      ciphertext = "04bf265bf33251906fb331051009c4cc76e34d308e0eb28e12eb22674f21fab2"
                   .. "2b8fea77668554992033f4f49c61c6a7436124b3ec422fc65a4771510697c1e0"
                   .. "1f3666abd0347f68c125a264e0d1c3d2",
    },
    -- TCFB8MMT2.rsp
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "fb978a0b6dc2c467e3cb52329de95161",
      iv         = "8b97579ea5ac300f",
      plaintext  = "80",
      ciphertext = "05",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "9b04c86dd31a8a589876101549d6e010",
      iv         = "52cd77d49fc72347",
      plaintext  = "2fef",
      ciphertext = "5818",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "fbb667e340586b5b5ef7c87049b93257",
      iv         = "459e8b8736715791",
      plaintext  = "061704",
      ciphertext = "93b378",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "4a575d02515d40b0a40d830bd9b31513",
      iv         = "ab27e9f02affa532",
      plaintext  = "55f75b95",
      ciphertext = "2ef5dddc",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "91a834855e6bab31c7fd6be657ceb9ec",
      iv         = "7838aaad4e64640b",
      plaintext  = "c3851c0ab4",
      ciphertext = "fe451f35f1",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "04d923abd9291c3e4954a8b52fdabcc8",
      iv         = "191f8794944e601c",
      plaintext  = "6fe8f67d2af1",
      ciphertext = "3bd78a8d24ad",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "a7799e7f5dfe54ce13376401e96de075",
      iv         = "370184c749d04a20",
      plaintext  = "2b4228b769795b",
      ciphertext = "6f32e4495e4259",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "6bfe3d3df8c1e0d34ffe0dbf854c940e",
      iv         = "51e4c5c29e858da6",
      plaintext  = "4cb3554fd0b9ec82",
      ciphertext = "72e1738d80d285e2",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "e0264aec13e63db991f8c120c4b9b6da",
      iv         = "bd8795dba79930d6",
      plaintext  = "79068e2943f02914af",
      ciphertext = "9b78c5636c5965f88e",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "7ca28938ba6bec1ffec78f7cd6976194",
      iv         = "953896586e49d38f",
      plaintext  = "2ea956d4a211db6859b7",
      ciphertext = "f20e536674a66fa73805",
    },
    -- TCFB8MMT3.rsp
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "9473ba2c29a87fec4f3829b3b6bc9e92434cab51890eda8c",
      iv         = "3420b13281d30b06",
      plaintext  = "cd",
      ciphertext = "22",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "b692ea4a62299b32d90451388a258fce3b3b1cfd34bc7f5d",
      iv         = "54c0b1efeff253a2",
      plaintext  = "32ee",
      ciphertext = "7c92",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "404902c85119dab61fb5ced6f46b45f8e5e06134a8b5c1b9",
      iv         = "a3d69732f94fffc7",
      plaintext  = "14c45c",
      ciphertext = "358d66",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "c4d345fddc9df7023b04e676528a2f57e051ba866b987aba",
      iv         = "d76fbd434d8b2ed9",
      plaintext  = "1d1e42cd",
      ciphertext = "44deeee3",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "f1c407f8250bcd10da914f626bf715548c31d6e0ba70ec5b",
      iv         = "0f9d3071af25a142",
      plaintext  = "a43ecd3d06",
      ciphertext = "6a6da48c70",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "267ccbeaa49125512c7f2c9e8af84ae63b9bb95783168a52",
      iv         = "03f656fb72c9bf5d",
      plaintext  = "ab1581707d7d",
      ciphertext = "16881e43fc0c",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "5efe5d40802f4f25adc2624cdc2980452c0b389152575280",
      iv         = "00167d7f48309f0a",
      plaintext  = "024e626cea4991",
      ciphertext = "2b239e41d96069",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "cb79b6dfada11379b65132a77054d30813b9da2954020e9e",
      iv         = "2c5f51cd900fe753",
      plaintext  = "5876dbe3d1e63bec",
      ciphertext = "73c154524f4d5729",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "04df08192964d6bcc84c97da940b32c880dfd0ce8c9180a8",
      iv         = "cf7e0cc1f223343e",
      plaintext  = "1de812279bd5576ec2",
      ciphertext = "34d1067d1a92a8da19",
    },
    {
      mode       = "cfb8",
      decrypt    = false,
      key        = "e3347a6b0bc1152c642a25cbd3bc31abfba162a81f197c15",
      iv         = "b740cc21e925e3c8",
      plaintext  = "dbe915fcb33bca18ef14",
      ciphertext = "f4801a8d039db4ca8ff6",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "0b9dc1f7e032fb9b1fa16e408531b9ade9d649ab046b1004",
      iv         = "ced325ff2fddc911",
      plaintext  = "18",
      ciphertext = "7a",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "6d2a5458aebcdf4a7cae103752fb021abf62c7e029431370",
      iv         = "fbda3bc9fdf9aa57",
      plaintext  = "79ad",
      ciphertext = "9d5b",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "5d15f7e05b6b349d3d9b73852f86ae13fba7fe57df7c38ba",
      iv         = "8b245ba333bf1510",
      plaintext  = "40cb41",
      ciphertext = "2685a3",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "15d0df5d9d94bc863813a77a7c705e239eb352d06dbc1623",
      iv         = "4ec627d7bce1e3ba",
      plaintext  = "33de3839",
      ciphertext = "f647e7bb",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "5e8f4f9bc11ad0da5237a7f84ae908abd570010becc1895b",
      iv         = "ef6d3f54266c978f",
      plaintext  = "fe122c92dd",
      ciphertext = "fb0a8ce668",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "49758a67aeb3c13768041cc4e961b916c7349b86d56726b9",
      iv         = "e3e741b6bda7599e",
      plaintext  = "5f8495b4f18f",
      ciphertext = "800a7f57d535",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "089d0da8bcb076b392b570cb40ce04b57986ea49fe1901d3",
      iv         = "e82b5c08b93504fe",
      plaintext  = "af0011c3bfa235",
      ciphertext = "bc6f93a5600683",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "a82f0e459280195713791ca4da40a89dfd4cf8d67ff2cb4f",
      iv         = "7d0eb17803f0f049",
      plaintext  = "09d4d412a467285a",
      ciphertext = "725e034c76d939ef",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "feb334c2139e32c46bead6c226ec70514c2fa2ae45804637",
      iv         = "e7afcc49c32f50f1",
      plaintext  = "f5734bf9e3c1612acc",
      ciphertext = "ab060d240bc383fc12",
    },
    {
      mode       = "cfb8",
      decrypt    = true,
      key        = "290dba49c12ae9676ef719ef6becad0d0479806e02e0706e",
      iv         = "2d5f4bed09214779",
      plaintext  = "e8cbdd0d7e8ac964ae2d",
      ciphertext = "ecb12ffea897768737af",
    },
    -- TOFBMMT2.rsp
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "15da6d4097c1b5bc026e3e3ee532f452",
      iv         = "dd0f8d8921e46c11",
      plaintext  = "a86df6791e482b72",
      ciphertext = "21c3f87a3f01bdf0",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "51267c61b5ab13709d2f3223c82fe923",
      iv         = "42fd7775e8377f79",
      plaintext  = "1e55328b68623e53364d271ecbc98a6b",
      ciphertext = "25b8e7d8fd54ee754e275ea4818c7ba8",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "157cbf40d6ec86da75f48f5b51d6b9ab",
      iv         = "c5dcd3e7b1753197",
      plaintext  = "49eae506b8879ff36eddf0a3bd2e48416be42f5734855999",
      ciphertext = "9e6325dc2f819c47bcb0cfadd3d4662300ddde424b3e2e36",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "5b16e90ebc8531cd92150d258f260eab",
      iv         = "29b89c2bfb83b3bb",
      plaintext  = "6a0f7b08d21eb115680b84b47bf826b5b775162da65f8773bf96d3299c3e0241",
      ciphertext = "a5db39cef5fcde051a6d2c77f0a8868b916f7532785ff01de7c8db2e85bccd2c",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "452a91929e327ff15268ea51cb015d80",
      iv         = "ed6a97d3c723d619",
      plaintext  = "814844304f2531315f2db20214e577676ef70148ffcbe668c1ddb0e34223dad7"
                   .. "ab0b91f6d076a0dc",
      ciphertext = "809d5d04c9fad71f186ca68c8b29725bc1df85c3e4a5e8b9e632c9c10a4c2005"
                   .. "a78493a42921964c",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "c8d3ae9efd4c4031efe0402f20495267",
      iv         = "470e4f7c190759c1",
      plaintext  = "1286f0973010fa2f332a112077416d70a45b877cba357e8871c395746c45dabe"
                   .. "9fd52ce7e9cda9e4bdeb565c718031b7",
      ciphertext = "7b27f87ac46438103e7f8f5cae7805108748c5825e7f2c689e2c20df7dfda3b3"
                   .. "2fa7a7da59882441c88b69cc634db098",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "0da1687364ce79b00208bf80fbf8b09e",
      iv         = "e4e5479c1f443bd7",
      plaintext  = "02314591c3a0bdfbd7a8ba07c47175a5f279a749cc94c48d0d51023e4be21695"
                   .. "519d5028ce693b781b7568d5d0f0710570633cfaf06292d3",
      ciphertext = "87cbdfb6eb4c9c07a1738d400e21e06b68c61c7d1b2ca9d16c9793d55c108b04"
                   .. "cffe2f14edf68b70c9d4dfe8400ba2a72539c8669bff41e0",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "9d75d915922f08a1f102cd68da1657ab",
      iv         = "ab67ad59065dee6c",
      plaintext  = "0e8da215f2b498ea88c432201f0dfdb95a6ac6549141bdd68e7d3cbc2d349691"
                   .. "4e56d3835c98176a59b40babb14b51ab6d6bac9489335e6e04f69a899e4cbbe1",
      ciphertext = "66c5a3080dd3ab96ad505c4b777a8cf413254cae37031b4e772259ff5fb6fe2d"
                   .. "bf198ba2461041ef5250910e0741d5459f013d4d00ac0cb494db0480556a1e15",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "547c01383868ae100e67459eab70ce54",
      iv         = "a7dde735b7e280b4",
      plaintext  = "33c671b2ab0bc2e14538c6df841c5cd80b8b4e8697bad09e0aba3e59e5a29bd4"
                   .. "2559f9257455b80e6b3ea8040941abeb8a0b8fbe3e5b1281f3d8fe740a653a42"
                   .. "411f307f4aad1e85",
      ciphertext = "10974a09389628240cf1da06ba27b14fb5f648bd122a0a9f32b4f48da1fb9c57"
                   .. "3e77733b9c7b475ba9520c6e8d8edbb5d59d3b30d19da0133a7131741815ce46"
                   .. "e32e528ae9e615c4",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "f438794fefd93191a834a8f452e5d5fd",
      iv         = "e85bac2624d9dae6",
      plaintext  = "4d37eadd661f4f8883f4c503aa8338187cce694aaa1f090a9ba0df492fa23979"
                   .. "53d34d26c34965c632db44938673bf91339f6f9af7d5812fb5f8f0f79d4d53a9"
                   .. "8933de3769f689edd2d2ba010d2da3b1",
      ciphertext = "47ed798aa80c9606fdf46a29f625c39c66b7a952464c891afd439370df2e6099"
                   .. "f386d8eff99e5379abd6febe441181db3f69ded461219c28f9da26a8670a6e88"
                   .. "dbabd5b75f304f6c18bdc202c897b005",
    },
    -- TOFBMMT3.rsp
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "e96154a2a8755bfd2c51d6a19767d526435d19b6982c6da7",
      iv         = "d9b423434cea15f3",
      plaintext  = "3193f8d9f69061bf",
      ciphertext = "0a7b1da07c99a3dd",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "8386c464efbff1a71ca84cbfbf760e322a078a2f6d1ff231",
      iv         = "15edcde1bd53c4c5",
      plaintext  = "327da40b70e356868d22151c96e7658e",
      ciphertext = "da190d06db6269efa06ae72a79b986b1",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "b9209ebc8cce624016f17a43a28a25151aab8cabb06b083b",
      iv         = "2c958273ea54967f",
      plaintext  = "5e26188fb45d093f6067ff5c4c14e04335c2dd74671953e9",
      ciphertext = "492a36f813d199d31121e5379af9a8205190f438bb180306",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "bf139207866bb65de976a8702f236434b3dcc837082352c2",
      iv         = "4cd5e1f5822b324c",
      plaintext  = "aaed11ce4c1e77ee37bcbc01981488606df7f806debe93aad18a802bb9d1f631",
      ciphertext = "84aba27af12f6cf96e1dc885b279dab0ba887c96b3bb0d290d540fa8966a6e2d",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "89b09e9b8c733779e5cd01948320b3b075c43e3de632e3c4",
      iv         = "376125031f18f6f0",
      plaintext  = "882c7a1139a5a8fd56f11dd086a765f752c1e554e34dbe920d65f4b68d60d0f7"
                   .. "8f4a82d074920b53",
      ciphertext = "e8d90439e306c3e3e9460039fd214f00f7effc0b59b60193e61c6e28a9f4fbd3"
                   .. "3925231e488a52d2",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "a440ba91bae562191f97df58ae587c198975d34573cbcba4",
      iv         = "0b3933675711b115",
      plaintext  = "80ee89f42d88119bbc874f70d3c73ed25d593ff1dc830bee0007ec3e78a82d50"
                   .. "08ebce6fdc1b7de91c8fc271c0307ac2",
      ciphertext = "bb2b2fb188ba69da7cc52b01607d3d1542249d0b11ec27cc6c6fc73f0f2823e0"
                   .. "aeeac48e30c666740202fe9370a5190d",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "641320948a2985c2ecec0dfb34b9044575fb2a0b103b7551",
      iv         = "9ac06368fa0e64e0",
      plaintext  = "ea00b366d32dae2d9cba941554849c0f762eacf3c973647585ba5e56b7ebb4d7"
                   .. "e682c373f7e22fcd4eeb28e836ceeb9683208b33762ef192",
      ciphertext = "b31940c4dd1d84fd6fda953c117f1f20e580c2d18f4efe39fc15e4c55aee886a"
                   .. "65155b4b434ab729eb25d89c69b4d5c93a6625f88032aee3",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "2cfbbc625bad3e54e601f252c420a83413e92a46c1a7e586",
      iv         = "bada00b1236c22fa",
      plaintext  = "70a89485405675665436b927ad9b7e3d7c3ea8cfda2530bdb9c9bee21b777b96"
                   .. "82f72077a76c546a6e7b34dc1aaf334ebd1c2410f343954cd0365f4717fd7be4",
      ciphertext = "51de0e2fee09c60da19713a6cd1b821fb2a23fd7b48076d2e09dd75f692a295f"
                   .. "1cda91e23e8352266e1e7c853861e8f40cf372560c94924ed9fd5edc497bf5eb",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "b3ae7613c4d03b7a23588a6e7c9b1fe56e43588ff74f8a32",
      iv         = "896265e43e5a7bea",
      plaintext  = "01a768f8002e80e8c75bbc2d481ddbdc5bc67d61c9c7db66a3bbb4f7d9a88be3"
                   .. "07810f6592efdb03f4505fb754011e4d5ad81b0c41f58d982ebbda17c019c393"
                   .. "e80edc9ffb6c403e",
      ciphertext = "92fbd90dc8615aef016a1a433fd8c56afa8d256825ae50ad8559ff5dccfce42e"
                   .. "56c3ef8d7ebf6a7597fd0e953b0c00a022bcaad92cbc172cc79ef5f941b6e07e"
                   .. "c7e1c2716a939a7d",
    },
    {
      mode       = "ofb",
      decrypt    = false,
      key        = "13f10bc8d5987c6d970de6d60152dce6da3b3b04b52c205d",
      iv         = "9d995c6211b4ec4d",
      plaintext  = "b694eb44897b59d397659d3b008180356f648a3454466a3e746f99fba4ec3b0c"
                   .. "d186469d44f5e53e24501fee3dc8b479ff964705ca32c2e769c6f7bbdce283b3"
                   .. "5a71f82f96ec3b8e42cd2a44d147822d",
      ciphertext = "a5f7eee826ee1e8bcb77d2ef6ffb56c9a3a543c4fd89a06b4f265bdaab1c2c03"
                   .. "b66c51439ad414f52a4fcbacea833a33d1610f80f933ab900ec047334fd33faf"
                   .. "c5c25917409f01e047bb8328352f7c45",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "5726ece05e4cfd76bacd7f98ec7aec37b6cebc8004bfa7df",
      iv         = "1d5b0e220ec2726d",
      plaintext  = "78900b14699f7c4f",
      ciphertext = "431c5a331e6b05a5",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "aba1cb4c38cdf8ef5431c197ae07d0ec8a796e01e98a080b",
      iv         = "151d1e0402a5db0c",
      plaintext  = "daadc100897cd8a0aedf3e508ab29da0",
      ciphertext = "57fe32922c1d425c1f9040941ee0a89a",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "3238fe15cb37f2a7b0f70e38cb989b89c4dadacd151013d0",
      iv         = "a625853b45977f9c",
      plaintext  = "0acdfd49d2726bbafa0569b5bf9e404023961f10b6d3a65c",
      ciphertext = "1ed997fba12c444228c629b8945159f7aec4ff4c1986f202",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "b90b8fba8002f2e9feb03bae51e9545d0daedcc2b0372c62",
      iv         = "475f7c6b7d95923d",
      plaintext  = "edd9a290b1ad75a4f9c598a8d003b7250e702fac72bc6e931cc53f2b87110519",
      ciphertext = "eacb76fb8f5e7defdb3bdf18b011a52f6f066b31b39eb46140df809036b3219c",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "0e61641c977c376ecbab0110dafdc7c8a208da8a7968529d",
      iv         = "2dbef20e4105d481",
      plaintext  = "7c3df6dccea959b08bab7a8d07a0fd17397bd3020bb2e2038bbbe12d724e3374"
                   .. "f7fe7f0118de6a0b",
      ciphertext = "0d6d25269910a79a8c8a7e85b876a979bd065f60299b54b3e49237edcc607f3e"
                   .. "9ce1678312ed3776",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "9b7cabcbe3e9df16c1b3aef85d942f4fc72cba04c1738fd5",
      iv         = "06b35991e0c19fb3",
      plaintext  = "2f8151edd97c2108a27d21a0503273ce3d5cc60281122075e3c695d3c3de10bf"
                   .. "ec193788829203db0022216bc7b38d2f",
      ciphertext = "1677d8d8615e0dbd657697e9c6e4d9bfaa47c4011b905643ad14619f60df8eab"
                   .. "c74ba1a86ad2fffc6a216de3636d1a61",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "92f72386d004e9a7370efef81c269ead1f4f4f190b2f0143",
      iv         = "eeb3e446f16bb90f",
      plaintext  = "3c8b758e3dc3501d46092a4bb0cf2a54174eb2bbf20eefea3ed1147bb60b1eb0"
                   .. "a7e43ebb1040af1dbb7136a1abfb047950c045085f175e62",
      ciphertext = "ad0ca8d9a5d480025b69e2bcd446ac76957416a11dfd4dc0b4a45ebe63d35685"
                   .. "44d5a7ccfc45ce3085c7338731f65171eb9d162fc0298db9",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "c846b65880199be3a7a7f7832a3e0defa776ab454689d6df",
      iv         = "85bcb61d560fa6cc",
      plaintext  = "294951ede2e4a702e39c91cdc00ca52102792b0622c56a6cc9cca43ef3370609"
                   .. "fcc630aa3a3c9f5ff6985e30428f0cfb6e2a3d62ead52c7044043f8caeabd140",
      ciphertext = "22cb932424b73837244feceaddefe8a2ef4a62cee05fb17760a9b218d1966ab1"
                   .. "063bed174b467e8ea634f7995dc46c11b8ab0b7508894681e81c3502c3b335e8",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "fe80ea91e5457f757f342fdf1fd9f1bc32298ac8587c8054",
      iv         = "07a1f8f1bb2e90aa",
      plaintext  = "83143e9ec99134c85fae013b6951470cae79ad7c8bbdefadc818477757abc63a"
                   .. "0d141e640b1f9dd4b042904ebc7a30b7de55ca08512026b503fb29a964c1bf68"
                   .. "effd2b96981f4083",
      ciphertext = "e569720ad5aeab8a1ad1a6abbf06d7e2f8032f2f5562eea03b47b9169542ec4b"
                   .. "c7773114e3fc52e420824b928838a45cf0ecfd2b2d73eb19854c023064803374"
                   .. "50cc59241f020e3e",
    },
    {
      mode       = "ofb",
      decrypt    = true,
      key        = "75cdd30745fbbc3104835426529b45e5fd102c7c8a9d1f1c",
      iv         = "09773da862ac17ee",
      plaintext  = "57ddb843ff451860ef4afc3e0e899789b37debc9f953415fb968676ffc528f8c"
                   .. "8e25ba1cac214df4fd0cecfb1989e59930922fb6d0b75883a52346284718f07e"
                   .. "7121109774fe4e140b1983c036c9f30c",
      ciphertext = "5914418e5d3b715542186fd2a5a8de6d59395ba101bab05cde354aa9e59aee8c"
                   .. "15bea72d07a30339c7fa7e86e2e63ff6c003029d34a756265268087281dedf83"
                   .. "d1aa89998eb6d69a15bf24b7e6111b4d",
    },
}

vectors.FIPS81 = {
    key = "0123456789abcdef",
    iv  = "1234567890abcdef",
    plaintext = "4e6f772069732074" .. "68652074696d6520" .. "666f7220616c6c20",
    ecb = "3fa40e8a984d4815" .. "6a271787ab8883f9" .. "893d51ec4b563b53",
    cbc = "e5c7cdde872bf27c" .. "43e934008c389c0f" .. "683788499a7c05f6",
    cfb = "f3096249c7f46e51" .. "a69e839b1a92f784" .. "03467133898ea622",
    ofb = "f3096249c7f46e51" .. "35f24a242eeb3d3f" .. "3d6d5be3255af8c3",
    cfb8 = { plaintext = "4e6f7720697320746865", ciphertext = "f31fda07011462ee187f" },
}

vectors.SP80067 = {
    key        = "0123456789abcdef" .. "23456789abcdef01" .. "456789abcdef0123",
    plaintext  = "5468652071756663" .. "6b2062726f776e20" .. "666f78206a756d70",   -- "The qufck brown fox jump"
    ciphertext = "a826fd8ce53b855f" .. "cce21c8112256fe6" .. "68d5c05dd9b6b900",
}

return vectors
