//! Crypto signature scanner: evidence-backed identification of cryptographic
//! algorithm fingerprints in untrusted input (source code, decompiler text,
//! assembly, constant dumps, or raw binary).
//!
//! Philosophy: a signature is DISTINGUISHING EVIDENCE, never proof. The
//! scanner locates published constant tables (AES S-box, SM4 FK/CK, SHA-2
//! round constants, ...), isolated well-known words (TEA delta, K-table
//! entries), and code-shape patterns (RC4 KSA, XTEA shifts), then aggregates
//! the independent evidence per algorithm into a confidence tier:
//!
//! - **High** — a full table of >= 32 bytes matched, or >= 3 independent
//!   evidence weights accumulated for the same algorithm.
//! - **Medium** — a distinctive prefix anchor (>= 8 contiguous verified
//!   bytes), a full short table (8..32 bytes), or exactly 2 weights.
//! - **Low** — a single constant in isolation. Always reported with an
//!   explicit caveat that the evidence is weak.
//!
//! Evidence is never double-counted: a single word that lies inside a table
//! region already matched by the same signature is dropped (its weight is
//! included in the table hit), and derived constants (TEA's shifted delta
//! forms) contribute at most one weight between them.
//!
//! Near-miss policy (deliberate): a table with corrupted bytes is reported
//! only by its strongest CONTIGUOUS verified prefix. If the first 8..16
//! bytes still match, the candidate surfaces as Medium; if the corruption
//! falls inside the first 8 bytes, the candidate is not reported at all.
//! Interior-only table fragments (table start absent) are never reported:
//! the false-positive rate of unanchored middle fragments is too high for
//! the evidence model.
//!
//! Endianness: word-shaped tables (SHA-2 K, SM4 FK/CK, Blowfish P/S) are
//! searched in big-endian (canonical/serialized) and little-endian (in-memory
//! x86 dump) layouts; the evidence names the layout that matched.
//!
//! Text mode tokenizes hex material — `0x`-prefixed literals, standalone hex
//! pairs, and `xxd`/`hexdump -C` style dump lines (address column excluded,
//! ASCII column after `|` excluded) — into byte segments and scans those with
//! the same byte machinery, so a table split across lines of an array literal
//! or a dump still matches contiguously.
//!
//! Bounds: input capped at 8 MiB, at most 64 reported candidates, 16
//! evidence entries and 16 locations per candidate, snippets capped at 200
//! bytes. All scans are linear with first-byte fast rejection.

use std::borrow::Cow;

use serde::Serialize;

use cybercipher_core::{
    Category, CostClass, ErrorKind, ExecutionContext, OpResult, OperationError, OperationRegistry,
    OperationSpec, ParamDefault, ParamKind, ParamMap, ParamOption, ParamSpec, Provenance, Security,
    Value, ValueKind,
};

// ------------------------------------------------------------ constants ---
/// Hard cap on scanned input size. Anything larger is rejected up front so
/// no unbounded scan can start.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of candidates in a report.
pub const MAX_CANDIDATES: usize = 64;
/// Maximum evidence entries reported per candidate (excess is summarized).
pub const MAX_EVIDENCE: usize = 16;
/// Maximum locations reported per candidate.
pub const MAX_LOCATIONS: usize = 16;
/// Maximum snippet length in bytes.
pub const SNIPPET_MAX: usize = 200;
/// Source-byte gap over which two hex tokens still count as one contiguous
/// chain (array literals span separators, newlines, and short comments).
const GAP_LINK_BYTES: usize = 64;
/// Longest standalone bare-hex run accepted as one token (hex chars).
const MAX_BARE_RUN_CHARS: usize = 1024;
/// Offsets collected per search hit before merging.
const OFFSETS_PER_HIT: usize = 8;

const AES_SBOX_HEX: &str =
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326\
363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0\
523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f\
503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d1973\
60814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d\
8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e\
613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0f\
b054bb16";
const AES_INV_SBOX_HEX: &str =
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432\
a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816\
d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805\
b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e673\
96ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4b\
c6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d\
2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e1691463\
55210c7d";
const AES_RCON_HEX: &str = "01020408102040801b36";

const SM4_SBOX_HEX: &str =
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa441326498606999c4250f4\
91ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa64707a7fcf37317ba\
83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d351e240e5e6358d1a225227c3b\
01217887d40046579fd327524c3602e7a0c4c89eeabf8ad240c738b5a3f7f2cef96115a1\
e0ae5da49b341a55ad933230f58cb1e31df6e22e8266ca60c02923ab0d534e6fd5db3745\
defd8e2f03ff6a726d6c5b518d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd\
2d74d012b8e5b4b08969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3e\
d7cb3948";
const SM4_FK_HEX: &str = "a3b1bac656aa3350677d9197b27022dc";
const SM4_CK_HEX: &str = "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5\
fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1\
f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6ed\
f4fb020910171e252c333a41484f565d646b7279";

const SHA256_K_HEX: &str =
    "428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5d807aa98\
12835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174e49b69c1efbe4786\
0fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da983e5152a831c66db00327c8\
bf597fc7c6e00bf3d5a7914706ca63511429296727b70a852e1b21384d2c6dfc53380d13\
650a7354766a0abb81c2c92e92722c85a2bfe8a1a81a664bc24b8b70c76c51a3d192e819\
d6990624f40e3585106aa07019a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a\
5b9cca4f682e6ff3748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7\
c67178f2";
const SHA256_IV_HEX: &str = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";

const SHA512_K_HEX: &str =
    "428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc3956c25b\
f348b53859f111f1b605d019923f82a4af194f9bab1c5ed5da6d8118d807aa98a3030242\
12835b0145706fbe243185be4ee4b28c550c7dc3d5ffb4e272be5d74f27b896f80deb1fe\
3b1696b19bdc06a725c71235c19bf174cf692694e49b69c19ef14ad2efbe4786384f25e3\
0fc19dc68b8cd5b5240ca1cc77ac9c652de92c6f592b02754a7484aa6ea6e4835cb0a9dc\
bd41fbd476f988da831153b5983e5152ee66dfaba831c66d2db43210b00327c898fb213f\
bf597fc7beef0ee4c6e00bf33da88fc2d5a79147930aa72506ca6351e003826f14292967\
0a0e6e7027b70a8546d22ffc2e1b21385c26c9264d2c6dfc5ac42aed53380d139d95b3df\
650a73548baf63de766a0abb3c77b2a881c2c92e47edaee692722c851482353ba2bfe8a1\
4cf10364a81a664bbc423001c24b8b70d0f89791c76c51a30654be30d192e819d6ef5218\
d69906245565a910f40e35855771202a106aa07032bbd1b819a4c116b8d2d0c81e376c08\
5141ab532748774cdf8eeb9934b0bcb5e19b48a8391c0cb3c5c95a634ed8aa4ae3418acb\
5b9cca4f7763e373682e6ff3d6b2b8a3748f82ee5defb2fc78a5636f43172f6084c87814\
a1f0ab728cc702081a6439ec90befffa23631e28a4506cebde82bde9bef9a3f7b2c67915\
c67178f2e372532bca273eceea26619cd186b8c721c0c207eada7dd6cde0eb1ef57d4f7f\
ee6ed17806f067aa72176fba0a637dc5a2c898a6113f9804bef90dae1b710b35131c471b\
28db77f523047d8432caab7b40c724933c9ebe0a15c9bebc431d67c49c100d4c4cc5d4be\
cb3e42b6597f299cfc657e2a5fcb6fab3ad6faec6c44198c4a475817";

const SHA1_K_HEX: &str = "5a8279996ed9eba18f1bbcdcca62c1d6";

const MD5_K_HEX: &str = "d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501698098d8\
8b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821f61e2562c040b340\
265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc821e1cde6c33707d6f4d50d87\
455a14eda9e3e905fcefa3f8676f02d98d2a4c8afffa39428771f6816d9d6122fde5380c\
a4beea444bdecfa9f6bb4b60bebfbc70289b7ec6eaa127fad4ef308504881d05d9d4d039\
e6db99e51fa27cf8c4ac5665f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92\
ffeff47d85845dd16fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bb\
eb86d391";
const MD5_IV_HEX: &str = "67452301efcdab8998badcfe10325476";

const SIGMA32_HEX: &str = "657870616e642033322d62797465206b"; // "expand 32-byte k"
const SIGMA16_HEX: &str = "657870616e642031362d62797465206b"; // "expand 16-byte k"

const BLOWFISH_P_HEX: &str =
    "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e6\
38d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b54709179216d5d98979fb1b";
const BLOWFISH_S_HEX: &str =
    "d1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f9924a19947\
b3916cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e0d95748f728eb658\
718bcd5882154aee7b54a41dc25a59b59c30d5392af26013c5d1b023286085f0ca417918\
b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60\
e65525f3aa55ab945748986263e8144055ca396a2aab10b6b4cc5c341141e8cea15486af\
7c72e993b3ee1411636fbc2a2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c\
7a325381289586773b8f48986b4bb9afc4bfe81b6628219361d809ccfb21a991487cac60\
5dec8032ef845d5de98575b1dc262302eb651b8823893e81d396acc50f6d6ff383f44239\
2e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a670c9c61abd388f06a51a0d2\
d8542f68960fa728ab5133a36eef0b6c137a3be4ba3bf0507efb2a98a1f1651d39af0176\
66ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebee06f75d885c12073401a449f\
56c16aa64ed3aa62363f77061bfedf72429b023d37d0d724d00a1248db0fead349f1c09b\
075372c980991b7b25d479d8f6e8def7e3fe501ab6794c3b976ce0bd04c006bac1a94fb6\
409f60c45e5c9ec2196a246368fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952c\
cc814544af5ebd09bee3d004de334afd660f2807192e4bb3c0cba85745c8740fd20b5f39\
b9d3fbdb5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc8ea5e9f8db3222f8\
3c7516dffd616b152f501ec8ad0552ab323db5fafd23876053317b483e00df829e5c57bb\
ca6f8ca01a87562edf1769dbd542a8f6287effc3ac6732c68c4f5573695b27b0bbca58c8\
e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b9a53e479b6f84565d28e49bc\
4bfb9790e1ddf2daa4cb7e3362fb1341cee4c6e8ef20cada36774c01d07e9efe2bf11fb4\
95dbda4dae909198eaad8e716b93d5a0d08ed1d0afc725e08e3c5b2f8e7594b78ff6e2fb\
f2122b648888b812900df01c4fad5ea0688fc31cd1cff191b3a8c1ad2f2f2218be0e1777\
ea752dfe8b021fa1e5a0cc0fb56f74e818acf3d6ce89e299b4a84fe0fd13e0b77cc43b81\
d2ada8d9165fa2668095770593cc7314211a1477e6ad206577b5fa86c75442f5fb9d35cf\
ebcdaf0c7b3e89a0d6411bd3ae1e7e4900250e2d2071b35e226800bb57b8e0af2464369b\
f009b91e5563911d59dfa6aa78c14389d95a537f207d5ba202e5b9c5832603766295cfa9\
11c819684e734a41b3472dca7b14a94a1b5100529a532915d60f573fbc9bc6e42b60a476\
81e6740008ba6fb5571be91ff296ec6b2a0dd915b6636521e7b9f9b6ff34052ec5855664\
53b02d5da99f8fa108ba47996e85076a4b7a70e9b5b32944db75092ec4192623ad6ea6b0\
49a7df7d9cee60b88fedb266ecaa8c71699a17ff5664526cc2b19ee1193602a575094c29\
a0591340e4183a3e3f54989a5b429d656b8fe4d699f73fd6a1d29c07efe830f54d2d38e6\
f0255dc14cdd20868470eb266382e9c6021ecc5e09686b3f3ebaefc93c9718146b6a70a1\
687f358452a0e286b79c5305aa5007373e07841c7fdeae5c8e7d44ec5716f2b8b03ada37\
f0500c0df01c1f040200b3ffae0cf51a3cb574b225837a58dc0921bdd19113f97ca92ff6\
9432477322f547013ae5e58137c2dadcc8b576349af3dda7a94461460fd0030eecc8c73e\
a4751e41e238cd993bea0e2f3280bba1183eb3314e548b384f6db9086f420d03f60a04bf\
2cb8129024977c795679b072bcaf89afde9a771fd9930810b38bae12dccf3f2e5512721f\
2e6b7124501adde69f84cd877a5847187408da17bc9f9abce94b7d8cec7aec3adb851dfa\
63094366c464c3d2ef1c18473215d908dd433b3724c2ba1612a14d432a65c45150940002\
133ae4dd71dff89e10314e5581ac77d65f11199b043556f1d7a3c76b3c11183b5924a509\
f28fe6ed97f1fbfa9ebabf2c1e153c6e86e34570eae96fb1860e5e0a5a3e2ab3771fe71c\
4e3d06fa2965dcb999e71d0f803e89d65266c8252e4cc9789c10b36ac6150eba94e2ea78\
a5fc3c531e0a2df4f2f74ea7361d2b3d1939260f19c279605223a708f71312b6ebadfe6e\
eac31f66e3bc4595a67bc883b17f37d1018cff28c332ddefbe6c5aa56558218568ab9802\
eecea50fdb2f953b2aef7dad5b6e2f841521b62829076170ecdd4775619f151013cca830\
eb61bd960334fe1eaa0363cfb5735c904c70a239d59e9e0bcbaade14eecc86bc60622ca7\
9cab5cabb2f3846e648b1eaf19bdf0caa02369b9655abb5040685a323c2ab4b3319ee9d5\
c021b8f79b540b19875fa09995f7997e623d7da8f837889a97e32d7711ed935f16681281\
0e358829c7e61fd696dedfa17858ba9957f584a51b2272639b83c3ff1ac24696cdb30aeb\
532e30548fd948e46dbc312858ebf2ef34c6ffeafe28ed61ee7c3c735d4a14d9e864b7e3\
42105d14203e13e045eee2b6a3aaabeadb6c4f15facb4fd0c742f442ef6abbb5654f3b1d\
41cd2105d81e799e86854dc7e44b476a3d816250cf62a1f25b8d2646fc8883a0c1c7b6a3\
7f1524c369cb749247848a0b5692b285095bbf00ad19489d1462b17423820e0058428d2a\
0c55f5ea1dadf43e233f70613372f0928d937e41d65fecf16c223bdb7cde3759cbee7460\
4085f2a7ce77326ea607808419f8509ee8efd85561d99735a969a7aac50c06c25a04abfc\
800bcadc9e447a2ec3453484fdd567050e1e9ec9db73dbd3105588cd675fda79e3674340\
c5c43465713e38d83d28f89ef16dff20153e21e78fb03d4ae6e39f2bdb83adf7e93d5a68\
948140f7f64c261c94692934411520f77602d4f7bcf46b2ed4a20068d40824713320f46a\
43b7d4b7500061af1e39f62e9724454614214f74bf8b88404d95fc1d96b591af70f4ddd3\
66a02f45bfbc09ec03bd97857fac6dd031cb850496eb27b355fd3941da2547e6abca0a9a\
28507825530429f40a2c86dae9b66dfb68dc1462d7486900680ec0a427a18dee4f3ffea2\
e887ad8cb58ce0067af4d6b6aace1e7cd3375fecce78a399406b2a4220fe9e35d9f385b9\
ee39d7ab3b124e8b1dc9faf74b6d185626a36631eae397b23a6efa74dd5b43326841e7f7\
ca7820fbfb0af54ed8feb397454056acba48952755533a3a20838d87fe6ba9b7d096954b\
55a867bca1159a58cca9296399e1db33a62a4a563f3125f95ef47e1c9029317cfdf8e802\
04272f7080bb155c05282ce395c11548e4c66d2248c1133fc70f86dc07f9c9ee41041f0f\
404779a45d886e17325f51ebd59bc0d1f2bcc18f41113564257b7834602a9c60dff8e8a3\
1f636c1b0e12b4c202e1329eaf664fd1cad181156b2395e0333e92e13b240b62eebeb922\
85b2a20ee6ba0d99de720c8c2da2f728d012784595b794fd647d0862e7ccf5f05449a36f\
877d48fac39dfd27f33e8d1e0a476341992eff743a6f6eabf4f8fd37a812dc60a1ebddf8\
991be14cdb6e6b0dc67b55106d672c372765d43bdcd0e804f1290dc7cc00ffa3b5390f92\
690fed0b667b9ffbcedb7d9ca091cf0bd9155ea3bb132f88515bad247b9479bf763bd6eb\
37392eb3cc1159798026e297f42e312d6842ada7c66a2b3b12754ccc782ef11c6a124237\
b79251e706a1bbe64bfb63501a6b101811caedfa3d25bdd8e2e1c3c9444216590a121386\
d90cec6ed5abea2a64af674eda86a85fbebfe98864e4c3fe9dbc8057f0f7c08660787bf8\
6003604dd1fd8346f6381fb07745ae04d736fccc83426b33f01eab71b08041873c005e5f\
77a057bebde8ae2455464299bf582e614e58f48ff2ddfda2f474ef388789bdc25366f9c3\
c8b38e74b475f25546fcd9b97aeb26618b1ddf84846a0e79915f95e2466e598e20b45770\
8cd55591c902de4cb90bace1bb8205d011a862487574a99eb77f19b6e0a9dc09662d09a1\
c4324633e85a1f0209f0be8c4a99a0251d6efe101ab93d1d0ba5a4dfa186f20f2868f169\
dcb7da83573906fea1e2ce9b4fcd7f5250115e01a70683faa002b5c40de6d0279af88c27\
773f8641c3604c0661a806b5f0177a28c0f586e0006058aa30dc7d6211e69ed72338ea63\
53c2dd94c2c21634bbcbee5690bcb6deebfc7da1ce591d766f05e4094b7c018839720a3d\
7c927c2486e3725f724d9db91ac15bb4d39eb8fced54557808fca5b5d83d7cd34dad0fc4\
1e50ef5eb161e6f8a28514d96c51133c6fd5c7e756e14ec4362abfceddc6c837d79a3234\
92638212670efa8e406000e03a39ce37d3faf5cfabc277375ac52d1b5cb0679e4fa33742\
d382274099bc9bbed5118e9dbf0f7315d62d1c7ec700c47bb78c1b6b21a19045b26eb1be\
6a366eb45748ab2fbc946e79c6a376d26549c2c8530ff8ee468dde7dd5730a1d4cd04dc6\
2939bbdba9ba4650ac9526e8be5ee304a1fad5f06a2d519a63ef8ce29a86ee22c089c2b8\
43242ef6a51e03aa9cf2d0a483c061ba9be96a4d8fe51550ba645bd62826a2f9a73a3ae1\
4ba99586ef5562e9c72fefd3f752f7da3f046f6977fa0a5980e4a91587b086019b09e6ad\
3b3ee593e990fd5a9e34d7972cf0b7d9022b8b5196d5ac3a017da67dd1cf3ed67c7d2d28\
1f9f25cfadf2b89b5ad6b4725a88f54ce029ac71e019a5e647b0acfded93fa9be8d3c48d\
283b57ccf8d5662979132e28785f0191ed756055f7960e44e3d35e8c15056dd488f46dba\
03a161250564f0bdc3eb9e153c9057a297271aeca93a072a1b3f6d9b1e6321f5f59c66fb\
26dcf3197533d928b155fdf5035634828aba3cbb28517711c20ad9f8abcc5167ccad925f\
4de817513830dc8e379d58629320f991ea7a90c2fb3e7bce5121ce64774fbe32a8b6e37e\
c3293d4648de53696413e680a2ae0810dd6db22469852dfd09072166b39a460a6445c0dd\
586cdecf1c20c8ae5bbef7dd1b588d40ccd2017f6bb4e3bbdda26a7e3a59ff453e350a44\
bcb4cdd572eacea8fa6484bb8d6612aebf3c6f47d29be463542f5d9eaec2771bf64e6370\
740e0d8de75b1357f8721671af537d5d4040cb084eb4e2cc34d2466a0115af84e1b00428\
95983a1d06b89fb4ce6ea0486f3f3b823520ab82011a1d4b277227f8611560b1e7933fdc\
bb3a792b344525bda08839e151ce794b2f32c9b7a01fbac9e01cc87ebcc7d1f6cf0111c3\
a1e8aac71a908749d44fbd9ad0dadecbd50ada380339c32ac69136678df9317ce0b12b4f\
f79e59b743f5bb3af2d519ff27d9459cbf97222c15e6fc2a0f91fc719b941525fae59361\
ceb69cebc2a8645912baa8d1b6c1075ee3056a0c10d25065cb03a442e0ec6e0e1698db3b\
4c98a0be3278e9649f1f9532e0d392dfd3a0342b8971f21e1b0a74414ba3348cc5be7120\
c37632d8df359f8d9b992f2ee60b6f470fe3f11de54cda541edad891ce6279cfcd3e7e6f\
1618b166fd2c1d05848fd2c5f6fb2299f523f357a632762393a8353156cccd02acf08162\
5a75ebb56e16369788d273ccde96629281b949d04c50901b71c65614e6c6c7bd327a140a\
45e1d006c3f27b9ac9aa53fd62a80f00bb25bfe235bdd2f671126905b2040222b6cbcf7c\
cd769c2b53113ec01640e3d338abbd602547adf0ba38209cf746ce7677afa1c520756060\
85cbfe4e8ae88dd87aaaf9b04cf9aa7e1948c25c02fb8a8c01c36ae4d6ebe1f990d4f869\
a65cdea03f09252dc208e69fb74e6132ce77e25b578fdfe33ac372e6";

// --------------------------------------------------------- public types ---

/// Confidence tier of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    fn from_weight_sum(sum: u32) -> Confidence {
        match sum {
            0 | 1 => Confidence::Low,
            2 => Confidence::Medium,
            _ => Confidence::High,
        }
    }
}

/// Detection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Text when the input is valid UTF-8, bytes otherwise.
    Auto,
    /// Tokenize hex material in source/asm/decompiler/dump text.
    Text,
    /// Raw binary subsequence search.
    Bytes,
}

impl ScanMode {
    fn parse(s: &str) -> Result<ScanMode, OperationError> {
        match s {
            "auto" => Ok(ScanMode::Auto),
            "text" => Ok(ScanMode::Text),
            "bytes" => Ok(ScanMode::Bytes),
            other => Err(OperationError::invalid_param(
                "mode",
                format!("unknown mode `{other}` — expected auto, text, or bytes"),
            )),
        }
    }
}

/// One located piece of evidence.
#[derive(Debug, Clone, Serialize)]
pub struct SigLocation {
    /// Byte offset into the scanned input.
    pub offset: usize,
    /// 1-based line (text mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-based column (text mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Bounded context snippet (<= 200 bytes).
    pub snippet: String,
}

/// One aggregated algorithm candidate.
#[derive(Debug, Clone, Serialize)]
pub struct SigCandidate {
    /// Machine identifier, e.g. `aes`.
    pub algorithm: &'static str,
    /// Human label, e.g. `AES (Rijndael)`.
    pub label: &'static str,
    pub confidence: Confidence,
    /// Human-readable evidence entries (capped).
    pub evidence: Vec<String>,
    /// Where the evidence was found (capped).
    pub locations: Vec<SigLocation>,
    /// What was matched and how much trust it deserves.
    pub explanation: String,
}

/// Full scan report.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Effective mode that was used: `text` or `bytes`.
    pub mode: String,
    pub scanned_bytes: usize,
    pub candidates: Vec<SigCandidate>,
}

// ------------------------------------------------- signature definitions ---

struct TableDef {
    part: &'static str,
    /// Canonical bytes as hex; big-endian word order for word tables.
    hex: &'static str,
    /// 0 = raw byte table; 4/8 = word table (little-endian layout searched
    /// too).
    word: usize,
}

struct SingleDef {
    part: &'static str,
    hex: &'static str,
    /// Also search the byte-reversed (little-endian) form.
    swap: bool,
    /// Derived form of another constant (shift/product): at most one weak
    /// part counts toward the confidence sum.
    weak: bool,
}

#[derive(Debug, Clone, Copy)]
enum PatternKind {
    /// XTEA key schedule: `sum` shifted both `<< 4` and `>> 5` on one line.
    XteaShape,
    /// RC4 KSA init: `s[i] = i`.
    Rc4Init,
    /// RC4 modular indexing: `s[` with `% 256` / `& 255` on one line.
    Rc4Mask,
    /// RC4 swap: `s[i]` and `s[j]` assigned on one line.
    Rc4Swap,
}

struct PatternDef {
    part: &'static str,
    kind: PatternKind,
}

struct SignatureDef {
    algorithm: &'static str,
    label: &'static str,
    tables: &'static [TableDef],
    singles: &'static [SingleDef],
    patterns: &'static [PatternDef],
    explanation: &'static str,
}

const WEAK_CAVEAT: &str = "Single-constant evidence is weak: this value also appears in \
unrelated algorithms, PRNGs, and ordinary data. Verify with additional evidence before \
claiming identification.";

static SIGNATURES: &[SignatureDef] = &[
    SignatureDef {
        algorithm: "aes",
        label: "AES (Rijndael)",
        tables: &[
            TableDef {
                part: "sbox",
                hex: AES_SBOX_HEX,
                word: 0,
            },
            TableDef {
                part: "inverse-sbox",
                hex: AES_INV_SBOX_HEX,
                word: 0,
            },
            TableDef {
                part: "rcon",
                hex: AES_RCON_HEX,
                word: 0,
            },
        ],
        singles: &[],
        patterns: &[],
        explanation: "AES (FIPS 197) S-box, inverse S-box, and Rcon are fixed published \
tables; the 256-byte S-box is essentially unique.",
    },
    SignatureDef {
        algorithm: "sm4",
        label: "SM4 (GB/T 32907-2016)",
        tables: &[
            TableDef {
                part: "fk",
                hex: SM4_FK_HEX,
                word: 4,
            },
            TableDef {
                part: "ck",
                hex: SM4_CK_HEX,
                word: 4,
            },
            TableDef {
                part: "sbox",
                hex: SM4_SBOX_HEX,
                word: 0,
            },
        ],
        singles: &[],
        patterns: &[],
        explanation: "SM4 FK, CK, and S-box are fixed published constants; CK is the \
arithmetic sequence (4i+j)*7 mod 256.",
    },
    SignatureDef {
        algorithm: "sha256",
        label: "SHA-224 / SHA-256",
        tables: &[
            TableDef {
                part: "k-table",
                hex: SHA256_K_HEX,
                word: 4,
            },
            TableDef {
                part: "iv",
                hex: SHA256_IV_HEX,
                word: 4,
            },
        ],
        singles: &[
            SingleDef {
                part: "k0",
                hex: "428a2f98",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "k1",
                hex: "71374491",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "k2",
                hex: "b5c0fbcf",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "k3",
                hex: "e9b5dba5",
                swap: true,
                weak: false,
            },
        ],
        patterns: &[],
        explanation: "SHA-224/256 (FIPS 180-4) round constants are the fractional parts of \
the cube roots of the first 64 primes; the IV words are fixed.",
    },
    SignatureDef {
        algorithm: "sha512",
        label: "SHA-384 / SHA-512",
        tables: &[TableDef {
            part: "k-table",
            hex: SHA512_K_HEX,
            word: 8,
        }],
        singles: &[
            SingleDef {
                part: "k0",
                hex: "428a2f98d728ae22",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "k1",
                hex: "7137449123ef65cd",
                swap: true,
                weak: false,
            },
        ],
        patterns: &[],
        explanation: "SHA-384/512 (FIPS 180-4) round constants are 80 64-bit words derived \
from the cube roots of the first 80 primes.",
    },
    SignatureDef {
        algorithm: "sha1",
        label: "SHA-1",
        tables: &[TableDef {
            part: "k-table",
            hex: SHA1_K_HEX,
            word: 4,
        }],
        singles: &[
            SingleDef {
                part: "k0",
                hex: "5a827999",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "k1",
                hex: "6ed9eba1",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "k2",
                hex: "8f1bbcdc",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "k3",
                hex: "ca62c1d6",
                swap: true,
                weak: false,
            },
        ],
        patterns: &[],
        explanation: "SHA-1 (FIPS 180-4) uses four fixed round constants, one per 20-word \
round group.",
    },
    SignatureDef {
        algorithm: "md5",
        label: "MD5",
        tables: &[
            TableDef {
                part: "t-table",
                hex: MD5_K_HEX,
                word: 4,
            },
            TableDef {
                part: "iv",
                hex: MD5_IV_HEX,
                word: 4,
            },
        ],
        singles: &[
            SingleDef {
                part: "t0",
                hex: "d76aa478",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "t1",
                hex: "e8c7b756",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "t2",
                hex: "242070db",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "t3",
                hex: "c1bdceee",
                swap: true,
                weak: false,
            },
        ],
        patterns: &[],
        explanation: "MD5 (RFC 1321) T-table entries are floor(|sin(i+1)| * 2^32); the IV \
67452301/efcdab89/98badcfe/10325476 is fixed.",
    },
    SignatureDef {
        algorithm: "tea",
        label: "TEA / XTEA / XXTEA",
        tables: &[],
        singles: &[
            SingleDef {
                part: "delta",
                hex: "9e3779b9",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "delta>>5",
                hex: "04f1bbcd",
                swap: true,
                weak: true,
            },
            SingleDef {
                part: "delta*32",
                hex: "c6ef3720",
                swap: true,
                weak: true,
            },
        ],
        patterns: &[PatternDef {
            part: "xtea-shape",
            kind: PatternKind::XteaShape,
        }],
        explanation: "TEA/XTEA/XXTEA share the golden-ratio delta 0x9E3779B9 and the \
(sum<<4)^(sum>>5) key-schedule shape. A lone delta also appears in unrelated hashing and \
PRNG code, so isolated hits are weak; the shifted/derived forms strengthen TEA-specific \
claims.",
    },
    SignatureDef {
        algorithm: "chacha",
        label: "ChaCha / Salsa",
        tables: &[
            TableDef {
                part: "sigma32",
                hex: SIGMA32_HEX,
                word: 0,
            },
            TableDef {
                part: "sigma16",
                hex: SIGMA16_HEX,
                word: 0,
            },
        ],
        singles: &[
            SingleDef {
                part: "sigma-word-0",
                hex: "61707865",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "sigma-word-1",
                hex: "3320646e",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "sigma-word-2",
                hex: "79622d32",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "sigma-word-3",
                hex: "6b206574",
                swap: true,
                weak: false,
            },
        ],
        patterns: &[],
        explanation: "ChaCha/Salsa (RFC 8439, D. J. Bernstein) start their state with the \
ASCII sigma constants \"expand 32-byte k\" / \"expand 16-byte k\" (words 0x61707865, \
0x3320646e, 0x79622d32, 0x6b206574).",
    },
    SignatureDef {
        algorithm: "rc4",
        label: "RC4 (arcfour)",
        tables: &[],
        singles: &[],
        patterns: &[
            PatternDef {
                part: "ksa-init",
                kind: PatternKind::Rc4Init,
            },
            PatternDef {
                part: "ksa-mask",
                kind: PatternKind::Rc4Mask,
            },
            PatternDef {
                part: "swap",
                kind: PatternKind::Rc4Swap,
            },
        ],
        explanation: "RC4 has no published constants: identification relies on the KSA/PRGA \
code shape (S-box init s[i]=i, mod-256 indexing, byte swaps). One shape alone is weak \
evidence; several independent shapes are needed for confidence.",
    },
    SignatureDef {
        algorithm: "blowfish",
        label: "Blowfish",
        tables: &[
            TableDef {
                part: "p-array",
                hex: BLOWFISH_P_HEX,
                word: 4,
            },
            TableDef {
                part: "s1",
                hex: BLOWFISH_S_HEX,
                word: 4,
            },
        ],
        singles: &[
            SingleDef {
                part: "p0",
                hex: "243f6a88",
                swap: true,
                weak: false,
            },
            SingleDef {
                part: "p1",
                hex: "85a308d3",
                swap: true,
                weak: false,
            },
        ],
        patterns: &[],
        explanation: "Blowfish P-array and S-boxes are the hexadecimal digits of pi; the \
full tables (18 + 4x256 words) are distinctive. P and S1 are pinned here as anchors.",
    },
];

/// Decode a hex constant string. The tables are static; malformed entries are
/// a programming error caught by debug assertions and the test suite.
fn unhex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = cleaned.as_bytes();
    debug_assert_eq!(bytes.len() % 2, 0, "odd-length hex constant {s:?}");
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        debug_assert_eq!(pair.len(), 2);
        let hi = (pair[0] as char).to_digit(16).unwrap_or(0);
        let lo = (pair[1] as char).to_digit(16).unwrap_or(0);
        out.push((hi * 16 + lo) as u8);
    }
    out
}

/// Reverse bytes within each word (canonical BE table -> in-memory LE dump).
fn word_swapped(bytes: &[u8], word: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for chunk in out.chunks_mut(word) {
        chunk.reverse();
    }
    out
}

fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x20..0x7f).contains(b))
}

// ----------------------------------------------------------- searching ----

/// A contiguous chain of hex tokens (text mode) or the whole input (bytes
/// mode). `src` maps each stream byte back to its source-byte offset.
struct Segment {
    bytes: Vec<u8>,
    src: Vec<u32>,
}

/// Kind of a table hit: the full table, or only a verified prefix anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HitKind {
    Anchor,
    Full,
}

#[derive(Clone)]
struct RawHit {
    part: &'static str,
    weight: u32,
    weak: bool,
    detail: String,
    /// Source offsets of the match starts.
    offsets: Vec<usize>,
}

/// Where a table match landed: source offsets of the match starts plus the
/// source ranges [start, end) they cover (used to suppress single-constant
/// hits already contained in a table match).
struct TableMatch {
    offsets: Vec<usize>,
    extents: Vec<(usize, usize)>,
}

fn find_all(haystack: &[u8], needle: &[u8], limit: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return out;
    }
    let first = needle[0];
    let mut start = 0usize;
    while start + needle.len() <= haystack.len() {
        let Some(rel) = haystack[start..].iter().position(|&b| b == first) else {
            break;
        };
        let pos = start + rel;
        if haystack[pos..pos + needle.len()] == *needle {
            out.push(pos);
            if out.len() >= limit {
                break;
            }
        }
        start = pos + 1;
    }
    out
}

fn full_weight(len: usize) -> u32 {
    if len >= 32 {
        3
    } else if len >= 8 {
        2
    } else {
        1
    }
}

fn layout_note(le: bool) -> &'static str {
    if le {
        " (little-endian layout)"
    } else {
        ""
    }
}

/// Search one byte pattern across all segments. Returns the hit kind (Full or
/// prefix Anchor) and where the matches landed.
fn search_pattern(segments: &[Segment], needle: &[u8]) -> Option<(HitKind, TableMatch)> {
    for seg in segments {
        let found = find_all(&seg.bytes, needle, OFFSETS_PER_HIT);
        if !found.is_empty() {
            let offsets: Vec<usize> = found.iter().map(|&p| seg.src[p] as usize).collect();
            let extents = found
                .iter()
                .map(|&p| {
                    let first = seg.src[p] as usize;
                    let last = seg.src[p + needle.len() - 1] as usize;
                    (first, last + 8)
                })
                .collect();
            return Some((HitKind::Full, TableMatch { offsets, extents }));
        }
    }
    // Full match failed: fall back to prefix anchors of 16 then 8 bytes.
    // A corruption inside the first 8 bytes yields no report (documented
    // near-miss policy in the module docs).
    for anchor_len in [needle.len().min(16), needle.len().min(8)] {
        if anchor_len < 8 || anchor_len >= needle.len() {
            continue;
        }
        for seg in segments {
            let found = find_all(&seg.bytes, &needle[..anchor_len], OFFSETS_PER_HIT);
            if !found.is_empty() {
                let offsets: Vec<usize> = found.iter().map(|&p| seg.src[p] as usize).collect();
                let extents = found
                    .iter()
                    .map(|&p| {
                        let first = seg.src[p] as usize;
                        let last = seg.src[p + anchor_len - 1] as usize;
                        (first, last + 8)
                    })
                    .collect();
                return Some((HitKind::Anchor, TableMatch { offsets, extents }));
            }
        }
    }
    None
}

fn covered_by(offset: usize, extents: &[(usize, usize)]) -> bool {
    extents.iter().any(|&(s, e)| offset >= s && offset < e)
}

/// Collect hits for a signature's tables (and, in text mode, printable-ASCII
/// tables searched as raw string literals). Table hits are collected first so
/// single-constant hits inside them can be suppressed.
fn collect_table_hits(
    sig: &SignatureDef,
    segments: &[Segment],
    text: Option<&str>,
    hits: &mut Vec<RawHit>,
    covered: &mut Vec<(usize, usize)>,
) {
    for table in sig.tables {
        let canonical = unhex(table.hex);
        let mut layouts: Vec<(bool, Cow<'_, [u8]>)> = vec![(false, Cow::Borrowed(&canonical))];
        if table.word > 0 {
            layouts.push((true, Cow::Owned(word_swapped(&canonical, table.word))));
        }
        for (le, needle) in layouts {
            if let Some((kind, m)) = search_pattern(segments, &needle) {
                let len = needle.len();
                let (weight, detail) = match kind {
                    HitKind::Full => (
                        full_weight(len),
                        format!(
                            "{part}: full {len}-byte table{note} at offset {off}",
                            part = table.part,
                            len = len,
                            note = layout_note(le),
                            off = m.offsets[0]
                        ),
                    ),
                    HitKind::Anchor => (
                        2,
                        format!(
                            "{part}: first {alen} bytes match the table prefix{note} at \
offset {off} — table not fully present",
                            part = table.part,
                            alen = needle.len().min(16).min(len),
                            note = layout_note(le),
                            off = m.offsets[0]
                        ),
                    ),
                };
                covered.extend(m.extents);
                hits.push(RawHit {
                    part: table.part,
                    weight,
                    weak: false,
                    detail,
                    offsets: m.offsets,
                });
            }
        }
        // Printable-ASCII tables (ChaCha sigma) also match as string literals
        // directly in text, outside the hex-token stream.
        if let Some(text) = text {
            if is_printable_ascii(&canonical) {
                let found = find_all(text.as_bytes(), &canonical, OFFSETS_PER_HIT);
                if !found.is_empty() {
                    let len = canonical.len();
                    let extents: Vec<(usize, usize)> =
                        found.iter().map(|&o| (o, o + len)).collect();
                    covered.extend(extents);
                    hits.push(RawHit {
                        part: table.part,
                        weight: full_weight(len),
                        weak: false,
                        detail: format!(
                            "{part}: {len}-byte ASCII literal at offset {off}",
                            part = table.part,
                            len = len,
                            off = found[0]
                        ),
                        offsets: found,
                    });
                }
            }
        }
    }
}

/// Collect hits for a signature's isolated constants. A constant lying
/// entirely inside an already-matched table region is suppressed (no double
/// counting — its weight is part of the table hit).
fn collect_single_hits(
    sig: &SignatureDef,
    segments: &[Segment],
    hits: &mut Vec<RawHit>,
    covered: &[(usize, usize)],
) {
    for single in sig.singles {
        let canonical = unhex(single.hex);
        let mut layouts: Vec<(bool, Cow<'_, [u8]>)> = vec![(false, Cow::Borrowed(&canonical))];
        if single.swap {
            layouts.push((true, Cow::Owned(canonical.iter().rev().copied().collect())));
        }
        for (le, needle) in layouts {
            for seg in segments {
                let found = find_all(&seg.bytes, &needle, OFFSETS_PER_HIT);
                let offsets: Vec<usize> = found.iter().map(|&p| seg.src[p] as usize).collect();
                let live: Vec<usize> = offsets
                    .iter()
                    .copied()
                    .filter(|&o| !covered_by(o, covered))
                    .collect();
                if live.is_empty() {
                    continue;
                }
                let weight = if needle.len() >= 8 { 2 } else { 1 };
                hits.push(RawHit {
                    part: single.part,
                    weight,
                    weak: single.weak,
                    detail: format!(
                        "{part}: constant 0x{hex}{note} at offset {off}",
                        part = single.part,
                        hex = single.hex,
                        note = layout_note(le),
                        off = live[0]
                    ),
                    offsets: live,
                });
                break;
            }
        }
    }
}

// ------------------------------------------------------ text tokenizer ----

struct SegBuilder {
    bytes: Vec<u8>,
    src: Vec<u32>,
    last_end: usize,
    open: bool,
}

struct Tokenizer {
    segments: Vec<Segment>,
    cur: SegBuilder,
}

impl Tokenizer {
    fn new() -> Tokenizer {
        Tokenizer {
            segments: Vec::new(),
            cur: SegBuilder {
                bytes: Vec::new(),
                src: Vec::new(),
                last_end: 0,
                open: false,
            },
        }
    }

    fn push_token(&mut self, bytes: &[u8], src_off: usize, src_len: usize) {
        let link = self.cur.open
            && src_off >= self.cur.last_end
            && src_off - self.cur.last_end <= GAP_LINK_BYTES;
        if !link {
            self.close_segment();
        }
        self.cur.open = true;
        self.cur.bytes.extend_from_slice(bytes);
        for i in 0..bytes.len() {
            self.cur.src.push((src_off + i) as u32);
        }
        self.cur.last_end = src_off + src_len;
    }

    fn close_segment(&mut self) {
        if self.cur.open && !self.cur.bytes.is_empty() {
            self.segments.push(Segment {
                bytes: std::mem::take(&mut self.cur.bytes),
                src: std::mem::take(&mut self.cur.src),
            });
        }
        self.cur.bytes.clear();
        self.cur.src.clear();
        self.cur.open = false;
    }

    fn finish(mut self) -> Vec<Segment> {
        self.close_segment();
        self.segments
    }
}

fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

struct Run {
    /// Byte offset of the first hex char.
    start: usize,
    /// Number of hex chars.
    len: usize,
    /// Preceded by `0x`/`0X` (prefix itself not part of an identifier).
    after_0x: bool,
    /// Bounded by non-identifier chars on both sides and not after `0x`.
    standalone: bool,
}

/// Collect maximal hex-char runs on one line, classified for tokenization.
/// Standalone runs are cut at the first `|` (hexdump ASCII columns); `0x`
/// literals are scanned on the whole line.
fn collect_runs(line: &[u8]) -> Vec<Run> {
    let pipe = line.iter().position(|&b| b == b'|');
    let mut runs = Vec::new();
    let mut i = 0usize;
    while i < line.len() {
        if !is_hex_byte(line[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < line.len() && is_hex_byte(line[i]) {
            i += 1;
        }
        let len = i - start;
        let after_0x = start >= 2
            && line[start - 2] == b'0'
            && (line[start - 1] == b'x' || line[start - 1] == b'X')
            && (start < 3 || !is_ident_byte(line[start - 3]));
        let scan_end = pipe.unwrap_or(line.len());
        let standalone = start < scan_end
            && !after_0x
            && (start == 0 || !is_ident_byte(line[start - 1]))
            && (start + len >= line.len() || !is_ident_byte(line[start + len]));
        runs.push(Run {
            start,
            len,
            after_0x,
            standalone,
        });
    }
    runs
}

/// Hex-digit token bytes for one run.
fn run_bytes(run: &Run, line: &[u8]) -> Option<Vec<u8>> {
    let digits = std::str::from_utf8(&line[run.start..run.start + run.len]).ok()?;
    if run.after_0x {
        if run.len == 0 || run.len > 16 {
            return None;
        }
        let value = u128::from_str_radix(digits, 16).ok()?;
        let width = run.len.div_ceil(2);
        let be = value.to_be_bytes();
        return Some(be[16 - width..].to_vec());
    }
    if run.len < 2 || !run.len.is_multiple_of(2) || run.len > MAX_BARE_RUN_CHARS {
        return None;
    }
    let mut out = Vec::with_capacity(run.len / 2);
    for pair in digits.as_bytes().chunks(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
    }
    Some(out)
}

/// Is `run` shaped like a hexdump address column? (4..=16 hex chars followed
/// by `:` — xxd — or by two spaces — `hexdump -C`.)
fn looks_like_address(run: &Run, line: &[u8]) -> bool {
    if !(4..=16).contains(&run.len) {
        return false;
    }
    let after = run.start + run.len;
    if after < line.len() && line[after] == b':' {
        return true;
    }
    after + 2 <= line.len() && line[after] == b' ' && line[after + 1] == b' '
}

/// Tokenize one line into the segment builder. Dump-style lines (>= 8 bytes
/// of standalone hex pairs) keep only their pair data; the address column and
/// anything past the `|` ASCII column are excluded.
fn process_line(tok: &mut Tokenizer, line: &[u8], base: usize) {
    let runs = collect_runs(line);
    let standalone: Vec<&Run> = runs
        .iter()
        .filter(|r| r.standalone && r.len >= 2 && r.len.is_multiple_of(2))
        .collect();
    let standalone_bytes: usize = standalone.iter().map(|r| r.len / 2).sum();

    if standalone_bytes >= 8 {
        // Dump-style line: drop a leading address column, keep pair data.
        let drop_first = standalone
            .first()
            .is_some_and(|r| looks_like_address(r, line));
        let data_runs: Vec<&Run> = standalone
            .iter()
            .enumerate()
            .filter(|(idx, _)| !(drop_first && *idx == 0))
            .map(|(_, r)| *r)
            .collect();
        let data_bytes: usize = data_runs.iter().map(|r| r.len / 2).sum();
        if data_bytes >= 8 {
            for run in data_runs {
                if let Some(bytes) = run_bytes(run, line) {
                    tok.push_token(&bytes, base + run.start, run.len);
                }
            }
            return;
        }
    }

    for run in &runs {
        if run.after_0x || run.standalone {
            if let Some(bytes) = run_bytes(run, line) {
                tok.push_token(&bytes, base + run.start, run.len);
            }
        }
    }
}

fn tokenize_text(text: &str) -> Vec<Segment> {
    let mut tok = Tokenizer::new();
    let bytes = text.as_bytes();
    let mut base = 0usize;
    while base <= bytes.len() {
        let rest = &bytes[base..];
        let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
            let mut end = rest.len();
            if end > 0 && rest[end - 1] == b'\r' {
                end -= 1;
            }
            process_line(&mut tok, &rest[..end], base);
            break;
        };
        let mut end = nl;
        if end > 0 && rest[end - 1] == b'\r' {
            end -= 1;
        }
        process_line(&mut tok, &rest[..end], base);
        base += nl + 1;
    }
    tok.finish()
}

// ---------------------------------------------------- pattern matching ----

fn pattern_matches(kind: PatternKind, line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    match kind {
        PatternKind::XteaShape => {
            l.contains("sum")
                && (l.contains("<< 4") || l.contains("<<4"))
                && (l.contains(">> 5") || l.contains(">>5"))
        }
        PatternKind::Rc4Init => l.contains("s[i]") && (l.contains("= i") || l.contains("=i")),
        PatternKind::Rc4Mask => {
            l.contains("s[")
                && (l.contains('%') || l.contains('&'))
                && (l.contains("256") || l.contains("255") || l.contains("0xff"))
        }
        PatternKind::Rc4Swap => l.contains("s[i]") && l.contains("s[j]") && l.contains('='),
    }
}

fn scan_text_hits(text: &str) -> (Vec<Segment>, Vec<RawHit>) {
    let segments = tokenize_text(text);
    let mut hits: Vec<RawHit> = Vec::new();
    let mut covered: Vec<(usize, usize)> = Vec::new();
    for sig in SIGNATURES {
        collect_table_hits(sig, &segments, Some(text), &mut hits, &mut covered);
        collect_single_hits(sig, &segments, &mut hits, &covered);
        for def in sig.patterns {
            let mut taken = 0usize;
            let mut line_start = 0usize;
            let bytes = text.as_bytes();
            let mut idx = 0usize;
            while line_start <= bytes.len() {
                let rest = &bytes[line_start..];
                let nl = rest.iter().position(|&b| b == b'\n');
                let end = line_start + nl.unwrap_or(rest.len());
                if taken >= 4 {
                    break;
                }
                let line = String::from_utf8_lossy(&bytes[line_start..end]);
                if pattern_matches(def.kind, &line) {
                    hits.push(RawHit {
                        part: def.part,
                        weight: 1,
                        weak: false,
                        detail: format!(
                            "{part}: code shape on line {line_no}",
                            part = def.part,
                            line_no = idx + 1
                        ),
                        offsets: vec![line_start],
                    });
                    taken += 1;
                }
                match nl {
                    Some(n) => {
                        line_start += n + 1;
                        idx += 1;
                    }
                    None => break,
                }
            }
        }
    }
    (segments, hits)
}

fn scan_bytes_hits(data: &[u8]) -> (Vec<Segment>, Vec<RawHit>) {
    let segments = vec![Segment {
        bytes: data.to_vec(),
        src: (0..data.len() as u32).collect(),
    }];
    let mut hits: Vec<RawHit> = Vec::new();
    let mut covered: Vec<(usize, usize)> = Vec::new();
    for sig in SIGNATURES {
        collect_table_hits(sig, &segments, None, &mut hits, &mut covered);
        collect_single_hits(sig, &segments, &mut hits, &covered);
    }
    (segments, hits)
}

// ------------------------------------------------------- aggregation ------

struct MergedPart {
    part: &'static str,
    weight: u32,
    weak: bool,
    details: Vec<String>,
    offsets: Vec<usize>,
}

fn merge_hits(hits: &[RawHit]) -> Vec<MergedPart> {
    let mut merged: Vec<MergedPart> = Vec::new();
    for hit in hits {
        if let Some(slot) = merged.iter_mut().find(|m| m.part == hit.part) {
            slot.details.push(hit.detail.clone());
            for off in &hit.offsets {
                if !slot.offsets.contains(off) {
                    slot.offsets.push(*off);
                }
            }
            // Keep the strongest weight seen for the part.
            slot.weight = slot.weight.max(hit.weight);
            slot.weak = slot.weak && hit.weak;
        } else {
            merged.push(MergedPart {
                part: hit.part,
                weight: hit.weight,
                weak: hit.weak,
                details: vec![hit.detail.clone()],
                offsets: hit.offsets.clone(),
            });
        }
    }
    for m in &mut merged {
        m.offsets.sort_unstable();
        m.offsets.truncate(MAX_LOCATIONS);
        m.details.truncate(MAX_EVIDENCE);
    }
    merged
}

fn aggregate(sig: &SignatureDef, hits: &[RawHit]) -> Option<(SigCandidate, Vec<usize>)> {
    if hits.is_empty() {
        return None;
    }
    // Stable order: by part appearance in the signature definition.
    let part_order = |p: &str| -> usize {
        sig.tables
            .iter()
            .position(|t| t.part == p)
            .or_else(|| sig.singles.iter().position(|s| s.part == p))
            .or_else(|| sig.patterns.iter().position(|s| s.part == p))
            .unwrap_or(usize::MAX)
    };
    let mut ordered: Vec<RawHit> = hits.to_vec();
    ordered.sort_by_key(|h| part_order(h.part));

    let parts = merge_hits(&ordered);
    let mut sum: u32 = 0;
    let mut weak_counted = false;
    for part in &parts {
        let mut w = part.weight;
        if part.weak {
            if weak_counted {
                w = 0;
            } else {
                weak_counted = true;
            }
        }
        sum += w;
    }
    let confidence = Confidence::from_weight_sum(sum);

    let mut evidence: Vec<String> = Vec::new();
    for part in &parts {
        evidence.extend(part.details.iter().cloned());
    }
    if evidence.len() > MAX_EVIDENCE {
        let dropped = evidence.len() - MAX_EVIDENCE;
        evidence.truncate(MAX_EVIDENCE);
        evidence.push(format!("+{dropped} more matching locations omitted"));
    }

    let mut explanation = sig.explanation.to_string();
    if confidence == Confidence::Low {
        explanation.push(' ');
        explanation.push_str(WEAK_CAVEAT);
    }

    let mut offsets: Vec<usize> = Vec::new();
    for part in &parts {
        for &off in &part.offsets {
            if !offsets.contains(&off) {
                offsets.push(off);
            }
        }
    }
    offsets.sort_unstable();
    offsets.truncate(MAX_LOCATIONS);

    Some((
        SigCandidate {
            algorithm: sig.algorithm,
            label: sig.label,
            confidence,
            evidence,
            locations: Vec::new(), // attached by the caller
            explanation,
        },
        offsets,
    ))
}

// ----------------------------------------------------- report building ----

fn snap_forward(text: &str, mut i: usize) -> usize {
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn clip_snippet(line: &str, hit_rel: usize) -> String {
    if line.len() <= SNIPPET_MAX {
        return line.to_string();
    }
    let start = snap_forward(line, hit_rel.saturating_sub(40));
    let end = snap_forward(line, (start + SNIPPET_MAX).min(line.len()));
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.push_str(&line[start..end]);
    if end < line.len() {
        out.push('…');
    }
    out
}

/// Compute (line, column, snippet) for sorted source offsets in one pass.
fn locate_text(text: &str, offsets: &[usize]) -> Vec<(u32, u32, String)> {
    let mut out = Vec::with_capacity(offsets.len());
    let bytes = text.as_bytes();
    let mut cursor = 0usize;
    let mut line_start = 0usize;
    let mut line_no = 1u32;
    for &off in offsets {
        let stop = off.min(bytes.len());
        while cursor < stop {
            if bytes[cursor] == b'\n' {
                line_no += 1;
                line_start = cursor + 1;
            }
            cursor += 1;
        }
        let line_end = bytes[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |p| line_start + p);
        let col = off.saturating_sub(line_start) + 1;
        let line_str = String::from_utf8_lossy(&bytes[line_start..line_end]).into_owned();
        let rel = off.saturating_sub(line_start).min(line_str.len());
        let snippet = clip_snippet(&line_str, rel);
        out.push((line_no, col as u32, snippet));
    }
    out
}

fn byte_snippet(data: &[u8], offset: usize) -> String {
    let start = offset.saturating_sub(16);
    let end = (start + 100).min(data.len());
    let mut out = String::with_capacity((end - start) * 2 + 2);
    if start > 0 {
        out.push('…');
    }
    for b in &data[start..end] {
        out.push_str(&format!("{b:02x}"));
    }
    if end < data.len() {
        out.push('…');
    }
    out
}

fn attach_locations(
    mut candidates: Vec<SigCandidate>,
    offsets_per_candidate: Vec<Vec<usize>>,
    text: Option<&str>,
    data: &[u8],
) -> Vec<SigCandidate> {
    for (cand, offsets) in candidates.iter_mut().zip(offsets_per_candidate) {
        match text {
            Some(text) => {
                cand.locations = locate_text(text, &offsets)
                    .into_iter()
                    .map(|(line, column, snippet)| SigLocation {
                        offset: 0,
                        line: Some(line),
                        column: Some(column),
                        snippet,
                    })
                    .collect();
                for (loc, &off) in cand.locations.iter_mut().zip(&offsets) {
                    loc.offset = off;
                }
            }
            None => {
                cand.locations = offsets
                    .iter()
                    .map(|&off| SigLocation {
                        offset: off,
                        line: None,
                        column: None,
                        snippet: byte_snippet(data, off),
                    })
                    .collect();
            }
        }
    }
    candidates
}

fn finish_candidates(data: &[u8], text: Option<&str>, hits: Vec<RawHit>) -> Vec<SigCandidate> {
    let mut candidates = Vec::new();
    let mut offsets_per_candidate = Vec::new();
    for sig in SIGNATURES {
        let sig_hits: Vec<RawHit> = hits
            .iter()
            .filter(|h| hit_is_from(sig, h))
            .cloned()
            .collect();
        if let Some((cand, offsets)) = aggregate(sig, &sig_hits) {
            candidates.push(cand);
            offsets_per_candidate.push(offsets);
        }
    }
    let mut candidates = attach_locations(candidates, offsets_per_candidate, text, data);
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.evidence.len().cmp(&a.evidence.len()))
            .then_with(|| a.algorithm.cmp(b.algorithm))
    });
    candidates.truncate(MAX_CANDIDATES);
    candidates
}

/// Does this hit belong to the signature? (Hits are tagged by part name which
/// is unique within a signature; a linear scan over all signatures' parts is
/// fine at this scale.)
fn hit_is_from(sig: &SignatureDef, hit: &RawHit) -> bool {
    sig.tables.iter().any(|t| t.part == hit.part)
        || sig.singles.iter().any(|s| s.part == hit.part)
        || sig.patterns.iter().any(|p| p.part == hit.part)
}

// ------------------------------------------------------------ scan API ----

/// Scan raw input. Text modes require valid UTF-8; `Auto` falls back to byte
/// mode for binary input. Input above [`MAX_INPUT_BYTES`] is rejected.
pub fn scan(input: &[u8], mode: ScanMode) -> Result<ScanReport, OperationError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!(
                "signature scan input is {size} bytes; the cap is {cap} bytes — split the \
input or scan a smaller file",
                size = input.len(),
                cap = MAX_INPUT_BYTES
            ),
        ));
    }
    let report = match mode {
        ScanMode::Bytes => scan_bytes(input),
        ScanMode::Text => {
            let text = std::str::from_utf8(input).map_err(|_| {
                OperationError::invalid_input(
                    "mode=text requires valid UTF-8 input (use mode=bytes for binary)",
                )
            })?;
            scan_text(text)
        }
        ScanMode::Auto => match std::str::from_utf8(input) {
            Ok(text) => scan_text(text),
            Err(_) => scan_bytes(input),
        },
    };
    Ok(report)
}

/// Scan source/asm/decompiler/hexdump text.
pub fn scan_text(text: &str) -> ScanReport {
    let (_segments, hits) = scan_text_hits(text);
    let candidates = finish_candidates(text.as_bytes(), Some(text), hits);
    ScanReport {
        mode: "text".to_string(),
        scanned_bytes: text.len(),
        candidates,
    }
}

/// Scan raw binary bytes.
pub fn scan_bytes(data: &[u8]) -> ScanReport {
    let (_segments, hits) = scan_bytes_hits(data);
    let candidates = finish_candidates(data, None, hits);
    ScanReport {
        mode: "bytes".to_string(),
        scanned_bytes: data.len(),
        candidates,
    }
}

// --------------------------------------------------------- registry op ----

static MODE_OPTIONS: &[ParamOption] = &[
    ParamOption {
        value: "auto",
        label: "Auto (text if UTF-8, else bytes)",
    },
    ParamOption {
        value: "text",
        label: "Text (source / asm / hexdump)",
    },
    ParamOption {
        value: "bytes",
        label: "Bytes (binary)",
    },
];

static CONF_OPTIONS: &[ParamOption] = &[
    ParamOption {
        value: "low",
        label: "Low (report weak evidence)",
    },
    ParamOption {
        value: "medium",
        label: "Medium",
    },
    ParamOption {
        value: "high",
        label: "High (strong evidence only)",
    },
];

static MODE_PARAM: ParamSpec = ParamSpec {
    key: "mode",
    label: "Mode",
    kind: ParamKind::Options,
    default: ParamDefault::Str("auto"),
    optional: false,
    hint: "Text tokenizes hex literals and dumps; bytes searches raw binary.",
    options: MODE_OPTIONS,
};

static HEX_PARAM: ParamSpec = ParamSpec {
    key: "input_is_hex",
    label: "Input is hex",
    kind: ParamKind::Boolean,
    default: ParamDefault::Bool(false),
    optional: false,
    hint: "Decode the input (hex string or hex dump) to bytes first, then scan in bytes mode.",
    options: &[],
};

static CONF_PARAM: ParamSpec = ParamSpec {
    key: "min_confidence",
    label: "Minimum confidence",
    kind: ParamKind::Options,
    default: ParamDefault::Str("low"),
    optional: false,
    hint: "Candidates below this tier are omitted.",
    options: CONF_OPTIONS,
};

static SCAN_SPEC: OperationSpec = OperationSpec {
    id: "crypto-signature-scan",
    name: "Crypto Signature Scan",
    description: "Identifies cryptographic algorithms in code, decompiler output, hex \
dumps, or binary by their published constant tables and code shapes (AES, SM4, SHA-1/2, \
MD5, TEA/XTEA, ChaCha/Salsa, RC4, Blowfish). Evidence-backed candidates with confidence — \
never single-constant certainty.",
    category: Category::Analysis,
    input_kinds: &[ValueKind::Text, ValueKind::Bytes],
    output_kind: ValueKind::Json,
    params: &[MODE_PARAM, HEX_PARAM, CONF_PARAM],
    cost: CostClass::Instant,
    security: Security::Neutral,
    deterministic: true,
    reversible: false,
    aliases: &[
        "sigscan",
        "signature scan",
        "identify algorithm",
        "find constants",
    ],
    tags: &["ctf", "analysis", "signatures", "constants"],
    provenance: Provenance {
        standard: "Published constants: FIPS 197, FIPS 180-4, RFC 1321, RFC 8439, \
GB/T 32907-2016, Blowfish spec (pi digits)",
        implementation: "CyberCipher native Rust",
        test_vectors: "CyberCipher unit tests",
    },
};

fn parse_confidence(s: &str) -> Result<Confidence, OperationError> {
    match s {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        other => Err(OperationError::invalid_param(
            "min_confidence",
            format!("unknown confidence `{other}` — expected low, medium, or high"),
        )),
    }
}

/// Decode a hex string / hex dump input (all whitespace ignored).
fn decode_hex_input(raw: &[u8]) -> Result<Vec<u8>, OperationError> {
    let cleaned: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(OperationError::decode(format!(
            "hex input has an odd number of digits ({len})",
            len = cleaned.len()
        )));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for (idx, pair) in cleaned.chunks(2).enumerate() {
        let digit = |b: u8, pos: usize| -> Result<u8, OperationError> {
            (b as char).to_digit(16).map(|d| d as u8).ok_or_else(|| {
                OperationError::decode(format!(
                    "invalid hex digit `{c}` at position {pos}",
                    c = b as char,
                    pos = pos
                ))
            })
        };
        let hi = digit(pair[0], idx * 2)?;
        let lo = digit(pair[1], idx * 2 + 1)?;
        out.push(hi * 16 + lo);
    }
    Ok(out)
}

fn scan_op(input: &Value, params: &ParamMap, _ctx: &ExecutionContext) -> OpResult<Value> {
    let mode = ScanMode::parse(params.str_or("mode", "auto"))?;
    let min_confidence = parse_confidence(params.str_or("min_confidence", "low"))?;
    let raw = input.as_bytes().ok_or_else(|| {
        OperationError::invalid_input("signature scan expects text or bytes input")
    })?;
    let effective_mode = if params.bool_or("input_is_hex", false) {
        ScanMode::Bytes
    } else {
        mode
    };
    let scan_input: Cow<'_, [u8]> = if params.bool_or("input_is_hex", false) {
        Cow::Owned(decode_hex_input(&raw)?)
    } else {
        Cow::Borrowed(&raw)
    };
    let mut report = scan(&scan_input, effective_mode)?;
    report.candidates.retain(|c| c.confidence >= min_confidence);
    Ok(Value::Json(
        serde_json::to_value(&report).unwrap_or_default(),
    ))
}

pub(crate) fn register(reg: &mut OperationRegistry) {
    reg.add_simple(&SCAN_SPEC, scan_op);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudorandom fill (no rand dependency).
    fn lcg_bytes(n: usize, seed: u32) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s.wrapping_mul(1664525).wrapping_add(1013904223);
                (s >> 24) as u8
            })
            .collect()
    }

    fn candidate<'a>(report: &'a ScanReport, algorithm: &str) -> &'a SigCandidate {
        report
            .candidates
            .iter()
            .find(|c| c.algorithm == algorithm)
            .unwrap_or_else(|| panic!("no candidate for {algorithm}"))
    }

    fn u32_be(bytes: &[u8], i: usize) -> u32 {
        u32::from_be_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ])
    }

    fn u64_be(bytes: &[u8], i: usize) -> u64 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        u64::from_be_bytes(w)
    }

    // ------------- constant integrity (real published tables) ------------

    #[test]
    fn aes_sbox_is_permutation_with_known_anchor() {
        let sbox = unhex(AES_SBOX_HEX);
        assert_eq!(sbox.len(), 256);
        let mut seen = [false; 256];
        for &b in &sbox {
            seen[b as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "S-box is not a permutation");
        assert_eq!(&sbox[..16], &unhex("637c777bf26b6fc53001672bfed7ab76")[..]);
        assert_eq!(sbox[0x52], 0x00, "the unique zero entry of the AES S-box");
        assert_eq!(
            unhex(AES_RCON_HEX),
            vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        );
    }

    #[test]
    fn aes_inv_sbox_inverts_sbox() {
        let sbox = unhex(AES_SBOX_HEX);
        let inv = unhex(AES_INV_SBOX_HEX);
        for i in 0..256 {
            assert_eq!(inv[sbox[i] as usize], i);
        }
    }

    #[test]
    fn sm4_sbox_is_permutation_and_ck_sequence() {
        let sbox = unhex(SM4_SBOX_HEX);
        assert_eq!(sbox.len(), 256);
        let mut seen = [false; 256];
        for &b in &sbox {
            seen[b as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "SM4 S-box is not a permutation");
        assert_eq!(&sbox[..4], &unhex("d690e9fe")[..]);
        let ck = unhex(SM4_CK_HEX);
        assert_eq!(&ck[..4], &unhex("00070e15")[..]);
        for i in 0..32 {
            for j in 0..4 {
                assert_eq!(ck[i * 4 + j], ((4 * i + j) * 7) % 256, "CK[{i}][{j}]");
            }
        }
        assert_eq!(unhex(SM4_FK_HEX), unhex("a3b1bac656aa3350677d9197b27022dc"));
    }

    #[test]
    fn sha256_k_matches_published_words() {
        let k = unhex(SHA256_K_HEX);
        assert_eq!(k.len(), 256);
        let first = [
            0x428a2f98u32,
            0x71374491,
            0xb5c0fbcf,
            0xe9b5dba5,
            0x3956c25b,
            0x59f111f1,
            0x923f82a4,
            0xab1c5ed5,
        ];
        for (i, w) in first.iter().enumerate() {
            assert_eq!(u32_be(&k, i), *w, "K[{i}]");
        }
        assert_eq!(u32_be(&k, 63), 0xc67178f2, "K[63]");
        assert_eq!(unhex(SHA256_IV_HEX)[0..4], unhex("6a09e667")[..]);
    }

    #[test]
    fn sha512_k_matches_published_words() {
        let k = unhex(SHA512_K_HEX);
        assert_eq!(k.len(), 640);
        assert_eq!(u64_be(&k, 0), 0x428a2f98d728ae22, "K[0]");
        assert_eq!(u64_be(&k, 1), 0x7137449123ef65cd, "K[1]");
        assert_eq!(u64_be(&k, 79), 0x6c44198c4a475817, "K[79]");
    }

    #[test]
    fn md5_t_table_matches_sine_derivation() {
        let t = unhex(MD5_K_HEX);
        assert_eq!(t.len(), 256);
        for i in 0..64 {
            let expect = (f64::sin((i + 1) as f64).abs() * 4294967296.0).floor() as u32;
            assert_eq!(u32_be(&t, i), expect, "T[{i}]");
        }
        assert_eq!(unhex(MD5_IV_HEX), unhex("67452301efcdab8998badcfe10325476"));
    }

    #[test]
    fn sha1_k_matches_published_constants() {
        assert_eq!(unhex(SHA1_K_HEX), unhex("5a8279996ed9eba18f1bbcdcca62c1d6"));
    }

    #[test]
    fn blowfish_tables_are_pi_digits() {
        let p = unhex(BLOWFISH_P_HEX);
        assert_eq!(p.len(), 72);
        assert_eq!(u32_be(&p, 0), 0x243f6a88);
        assert_eq!(u32_be(&p, 1), 0x85a308d3);
        let s1 = unhex(BLOWFISH_S_HEX);
        assert_eq!(s1.len(), 1024);
        assert_eq!(u32_be(&s1, 0), 0xd1310ba6);
        assert_eq!(u32_be(&s1, 1), 0x98dfb5ac);
    }

    #[test]
    fn chacha_sigma_is_ascii() {
        assert_eq!(unhex(SIGMA32_HEX), b"expand 32-byte k".to_vec());
        assert_eq!(unhex(SIGMA16_HEX), b"expand 16-byte k".to_vec());
    }

    #[test]
    fn tea_delta_constants() {
        assert_eq!(unhex("9e3779b9"), 0x9E3779B9u32.to_be_bytes().to_vec());
        assert_eq!(
            unhex("04f1bbcd"),
            (0x9E3779B9u32 >> 5).to_be_bytes().to_vec()
        );
        assert_eq!(
            unhex("c6ef3720"),
            0x9E3779B9u32.wrapping_mul(32).to_be_bytes().to_vec()
        );
    }

    // ------------------------- bytes mode --------------------------------

    #[test]
    fn bytes_full_sbox_is_high_at_known_offset() {
        let mut blob = lcg_bytes(4096, 7);
        let sbox = unhex(AES_SBOX_HEX);
        blob[37..37 + 256].copy_from_slice(&sbox);
        let report = scan_bytes(&blob);
        let aes = candidate(&report, "aes");
        assert_eq!(aes.confidence, Confidence::High);
        assert_eq!(aes.locations[0].offset, 37);
        assert!(aes
            .evidence
            .iter()
            .any(|e| e.contains("full 256-byte table")));
    }

    #[test]
    fn bytes_sm4_fk_plus_ck_is_high_fk_alone_is_medium() {
        let fk = unhex(SM4_FK_HEX);
        let ck = unhex(SM4_CK_HEX);

        let mut both = lcg_bytes(512, 9);
        both[64..64 + fk.len()].copy_from_slice(&fk);
        both[64 + fk.len()..64 + fk.len() + ck.len()].copy_from_slice(&ck);
        let report = scan_bytes(&both);
        assert_eq!(candidate(&report, "sm4").confidence, Confidence::High);

        let mut alone = lcg_bytes(512, 9);
        alone[64..64 + fk.len()].copy_from_slice(&fk);
        let report = scan_bytes(&alone);
        let sm4 = candidate(&report, "sm4");
        assert_eq!(sm4.confidence, Confidence::Medium);
        assert!(sm4
            .evidence
            .iter()
            .any(|e| e.contains("fk: full 16-byte table")));
    }

    #[test]
    fn bytes_sha256_k_detected_in_little_endian_layout() {
        let mut blob = lcg_bytes(2048, 13);
        let k = unhex(SHA256_K_HEX);
        let le = word_swapped(&k, 4);
        blob[100..100 + k.len()].copy_from_slice(&le);
        let report = scan_bytes(&blob);
        let sha = candidate(&report, "sha256");
        assert_eq!(sha.confidence, Confidence::High);
        assert!(sha.evidence.iter().any(|e| e.contains("little-endian")));
    }

    #[test]
    fn bytes_near_miss_tail_flip_is_medium_prefix_anchor() {
        let mut blob = lcg_bytes(1024, 11);
        let mut sbox = unhex(AES_SBOX_HEX);
        let last = sbox.len() - 1;
        sbox[last] ^= 0xff;
        blob[64..64 + 256].copy_from_slice(&sbox);
        let report = scan_bytes(&blob);
        let aes = candidate(&report, "aes");
        // Documented policy: >= 8 contiguous verified prefix bytes -> Medium.
        assert_eq!(aes.confidence, Confidence::Medium);
        assert!(aes.evidence.iter().any(|e| e.contains("prefix")));
    }

    #[test]
    fn bytes_near_miss_head_corruption_is_not_reported() {
        let mut blob = lcg_bytes(1024, 11);
        let mut sbox = unhex(AES_SBOX_HEX);
        sbox[3] ^= 0x01; // inside the first 8 bytes: below the anchor floor
        blob[64..64 + 256].copy_from_slice(&sbox);
        let report = scan_bytes(&blob);
        assert!(report.candidates.iter().all(|c| c.algorithm != "aes"));
    }

    #[test]
    fn bytes_chacha_sigma_medium_then_words_high() {
        let sigma = unhex(SIGMA32_HEX);
        let mut blob = lcg_bytes(512, 17);
        blob[32..32 + sigma.len()].copy_from_slice(&sigma);
        let report = scan_bytes(&blob);
        assert_eq!(candidate(&report, "chacha").confidence, Confidence::Medium);

        for (i, w) in ["61707865", "3320646e", "79622d32", "6b206574"]
            .iter()
            .enumerate()
        {
            let b = unhex(w);
            let at = 200 + i * 32;
            blob[at..at + 4].copy_from_slice(&b);
        }
        let report = scan_bytes(&blob);
        assert_eq!(candidate(&report, "chacha").confidence, Confidence::High);
    }

    #[test]
    fn bytes_blowfish_p_array_is_high() {
        let mut blob = lcg_bytes(512, 19);
        let p = unhex(BLOWFISH_P_HEX);
        blob[10..10 + p.len()].copy_from_slice(&p);
        let report = scan_bytes(&blob);
        assert_eq!(candidate(&report, "blowfish").confidence, Confidence::High);
    }

    #[test]
    fn bytes_rcon_alone_is_medium() {
        let mut blob = lcg_bytes(256, 23);
        let rcon = unhex(AES_RCON_HEX);
        blob[50..50 + rcon.len()].copy_from_slice(&rcon);
        let report = scan_bytes(&blob);
        assert_eq!(candidate(&report, "aes").confidence, Confidence::Medium);
    }

    #[test]
    fn bytes_single_delta_is_low_with_caveat() {
        let mut blob = lcg_bytes(256, 29);
        blob[77..81].copy_from_slice(&unhex("9e3779b9"));
        let report = scan_bytes(&blob);
        let tea = candidate(&report, "tea");
        assert_eq!(tea.confidence, Confidence::Low);
        assert!(tea.explanation.contains("weak"));
    }

    #[test]
    fn bytes_random_data_yields_nothing() {
        let blob = lcg_bytes(65536, 42);
        let report = scan_bytes(&blob);
        assert!(report.candidates.is_empty(), "unexpected: {report:?}");
    }

    // ------------------------- text mode ---------------------------------

    #[test]
    fn text_tea_delta_literal_low_with_line_column() {
        let src = "uint32_t sum = 0;\nvoid enc(void) { sum += 0x9E3779B9; }\n";
        let report = scan_text(src);
        let tea = candidate(&report, "tea");
        assert_eq!(tea.confidence, Confidence::Low);
        assert!(tea.explanation.contains("weak"));
        let loc = &tea.locations[0];
        assert_eq!(loc.line, Some(2));
        let col = src.lines().nth(1).unwrap().find("9E3779B9").unwrap() as u32 + 1;
        assert_eq!(loc.column, Some(col));
        assert!(loc.snippet.contains("0x9E3779B9"));
    }

    #[test]
    fn text_xtea_shape_plus_delta_is_medium() {
        let src = "v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);\n\
                  sum += 0x9E3779B9;\n";
        let report = scan_text(src);
        let tea = candidate(&report, "tea");
        assert_eq!(tea.confidence, Confidence::Medium);
        assert!(tea.evidence.iter().any(|e| e.contains("xtea-shape")));
        assert!(tea.evidence.iter().any(|e| e.contains("delta")));
    }

    #[test]
    fn text_c_array_literal_full_sbox_is_high() {
        let sbox = unhex(AES_SBOX_HEX);
        let mut src = String::from("static const uint8_t sbox[256] = {\n");
        for chunk in sbox.chunks(16) {
            src.push_str("    ");
            for b in chunk {
                src.push_str(&format!("0x{b:02x}, "));
            }
            src.push('\n');
        }
        src.push_str("};\n");
        let report = scan_text(&src);
        let aes = candidate(&report, "aes");
        assert_eq!(aes.confidence, Confidence::High);
        assert!(aes
            .evidence
            .iter()
            .any(|e| e.contains("full 256-byte table")));
        assert_eq!(aes.locations[0].line, Some(2));
    }

    #[test]
    fn text_sha1_constants_not_double_counted() {
        let src =
            "static const uint32_t k[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };";
        let report = scan_text(src);
        let sha1 = candidate(&report, "sha1");
        // The full 16-byte K table matches once; the per-word singles inside
        // the matched region are suppressed (no double counting), so this
        // stays Medium instead of inflating to High.
        assert_eq!(sha1.confidence, Confidence::Medium);
        assert_eq!(sha1.evidence.len(), 1);
    }

    #[test]
    fn text_rc4_structure_confidence_scales_with_shapes() {
        let init = "for (i = 0; i < 256; i++) s[i] = i;\n";
        let mask = "j = (j + s[i] + key[i % 256]) % 256;\n";
        let swap = "tmp = s[i]; s[i] = s[j]; s[j] = tmp;\n";

        let one = scan_text(init);
        assert_eq!(candidate(&one, "rc4").confidence, Confidence::Low);

        let two = format!("{init}{mask}");
        let report = scan_text(&two);
        assert_eq!(candidate(&report, "rc4").confidence, Confidence::Medium);

        let three = format!("{init}{mask}{swap}");
        let report = scan_text(&three);
        assert_eq!(candidate(&report, "rc4").confidence, Confidence::High);
    }

    #[test]
    fn text_sigma_string_literal_detected() {
        let src = "void chacha_init(uint32_t st[16]) { st[0] = 0x61707865; \
memcpy(&st[4], \"expand 32-byte k\", 16); }\n";
        let report = scan_text(src);
        let chacha = candidate(&report, "chacha");
        assert_eq!(chacha.confidence, Confidence::High);
        assert!(chacha.evidence.iter().any(|e| e.contains("ASCII literal")));
    }

    #[test]
    fn text_xxd_dump_full_table_detected() {
        let sbox = unhex(AES_SBOX_HEX);
        let mut dump = String::new();
        for (row, chunk) in sbox.chunks(16).enumerate() {
            let mut hexcols = String::new();
            for pair in chunk.chunks(2) {
                hexcols.push_str(&format!("{:02x}{:02x} ", pair[0], pair[1]));
            }
            dump.push_str(&format!("{:08x}: {hexcols} |sbox|\n", row * 16));
        }
        let report = scan_text(&dump);
        let aes = candidate(&report, "aes");
        assert_eq!(aes.confidence, Confidence::High);
        assert_eq!(aes.locations[0].offset, 10); // right after "00000000: "
        assert_eq!(aes.locations[0].line, Some(1));
    }

    #[test]
    fn text_hexdump_c_style_detected() {
        let sbox = unhex(AES_SBOX_HEX);
        let ascii = "c.w{.ko.";
        let mut dump = String::new();
        for (row, chunk) in sbox.chunks(16).enumerate() {
            let hexcols: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
            dump.push_str(&format!("{:08x}  {hexcols} |{ascii}|\n", row * 16));
        }
        let report = scan_text(&dump);
        assert_eq!(candidate(&report, "aes").confidence, Confidence::High);
    }

    #[test]
    fn text_plain_prose_yields_nothing() {
        let src = "The quick brown fox jumps over the lazy dog. Nothing to see here.\n";
        let report = scan_text(src);
        assert!(report.candidates.is_empty(), "unexpected: {report:?}");
    }

    // --------------------- bounds & registry ------------------------------

    #[test]
    fn oversized_input_rejected() {
        let data = vec![0xA5u8; MAX_INPUT_BYTES + 1];
        assert!(scan(&data, ScanMode::Bytes).is_err());
        assert!(scan(&data[..MAX_INPUT_BYTES], ScanMode::Bytes).is_ok());
    }

    #[test]
    fn registry_op_roundtrip_and_min_confidence_filter() {
        let reg = crate::default_registry();
        let op = reg.get("crypto-signature-scan").expect("op registered");

        let mut params = ParamMap::new();
        params.insert("mode", "text");
        params.insert("min_confidence", "medium");
        let src = "x += 0x9E3779B9; // weak single constant\n";
        let out = op
            .execute(
                &Value::Text(src.to_string()),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap();
        match out {
            Value::Json(json) => {
                let candidates = json["candidates"].as_array().unwrap();
                assert!(
                    candidates.is_empty(),
                    "tea Low candidate must be filtered out: {candidates:?}"
                );
            }
            other => panic!("expected JSON output, got {other:?}"),
        }
    }

    #[test]
    fn registry_op_hex_input_scans_decoded_bytes() {
        let reg = crate::default_registry();
        let op = reg.get("crypto-signature-scan").unwrap();
        let mut blob = lcg_bytes(300, 3);
        let sbox = unhex(AES_SBOX_HEX);
        blob[40..40 + 256].copy_from_slice(&sbox);
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();

        let mut params = ParamMap::new();
        params.insert("input_is_hex", true);
        let out = op
            .execute(&Value::Text(hex), &params, &ExecutionContext::new())
            .unwrap();
        match out {
            Value::Json(json) => {
                assert_eq!(json["mode"], "bytes");
                let candidates = json["candidates"].as_array().unwrap();
                let aes = candidates
                    .iter()
                    .find(|c| c["algorithm"] == "aes")
                    .expect("aes candidate");
                assert_eq!(aes["confidence"], "high");
                assert_eq!(aes["locations"][0]["offset"].as_u64(), Some(40));
            }
            other => panic!("expected JSON output, got {other:?}"),
        }
    }

    #[test]
    fn registry_op_rejects_bad_hex() {
        let reg = crate::default_registry();
        let op = reg.get("crypto-signature-scan").unwrap();
        let mut params = ParamMap::new();
        params.insert("input_is_hex", true);
        let err = op
            .execute(
                &Value::Text("zzzz".to_string()),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert!(err.message.contains("invalid hex digit"));
    }

    #[test]
    fn candidates_sorted_by_confidence() {
        let mut blob = lcg_bytes(1024, 31);
        let sbox = unhex(AES_SBOX_HEX);
        blob[0..256].copy_from_slice(&sbox);
        blob[900..904].copy_from_slice(&unhex("9e3779b9"));
        let report = scan_bytes(&blob);
        assert!(report.candidates.len() >= 2);
        for pair in report.candidates.windows(2) {
            assert!(pair[0].confidence >= pair[1].confidence);
        }
        assert_eq!(report.candidates[0].algorithm, "aes");
    }
}
