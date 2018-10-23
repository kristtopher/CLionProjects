#include <iostream>


#include "tomcrypt.h"

static const ulong32 S1[256] = {
0x30fb40d4UL, 0x9fa0ff0bUL, 0x6beccd2fUL, 0x3f258c7aUL, 0x1e213f2fUL, 0x9c004dd3UL,
0x6003e540UL, 0xcf9fc949UL, 0xbfd4af27UL, 0x88bbbdb5UL, 0xe2034090UL, 0x98d09675UL,
0x6e63a0e0UL, 0x15c361d2UL, 0xc2e7661dUL, 0x22d4ff8eUL, 0x28683b6fUL, 0xc07fd059UL,
0xff2379c8UL, 0x775f50e2UL, 0x43c340d3UL, 0xdf2f8656UL, 0x887ca41aUL, 0xa2d2bd2dUL,
0xa1c9e0d6UL, 0x346c4819UL, 0x61b76d87UL, 0x22540f2fUL, 0x2abe32e1UL, 0xaa54166bUL,
0x22568e3aUL, 0xa2d341d0UL, 0x66db40c8UL, 0xa784392fUL, 0x004dff2fUL, 0x2db9d2deUL,
0x97943facUL, 0x4a97c1d8UL, 0x527644b7UL, 0xb5f437a7UL, 0xb82cbaefUL, 0xd751d159UL,
0x6ff7f0edUL, 0x5a097a1fUL, 0x827b68d0UL, 0x90ecf52eUL, 0x22b0c054UL, 0xbc8e5935UL,
0x4b6d2f7fUL, 0x50bb64a2UL, 0xd2664910UL, 0xbee5812dUL, 0xb7332290UL, 0xe93b159fUL,
0xb48ee411UL, 0x4bff345dUL, 0xfd45c240UL, 0xad31973fUL, 0xc4f6d02eUL, 0x55fc8165UL,
0xd5b1caadUL, 0xa1ac2daeUL, 0xa2d4b76dUL, 0xc19b0c50UL, 0x882240f2UL, 0x0c6e4f38UL,
0xa4e4bfd7UL, 0x4f5ba272UL, 0x564c1d2fUL, 0xc59c5319UL, 0xb949e354UL, 0xb04669feUL,
0xb1b6ab8aUL, 0xc71358ddUL, 0x6385c545UL, 0x110f935dUL, 0x57538ad5UL, 0x6a390493UL,
0xe63d37e0UL, 0x2a54f6b3UL, 0x3a787d5fUL, 0x6276a0b5UL, 0x19a6fcdfUL, 0x7a42206aUL,
0x29f9d4d5UL, 0xf61b1891UL, 0xbb72275eUL, 0xaa508167UL, 0x38901091UL, 0xc6b505ebUL,
0x84c7cb8cUL, 0x2ad75a0fUL, 0x874a1427UL, 0xa2d1936bUL, 0x2ad286afUL, 0xaa56d291UL,
0xd7894360UL, 0x425c750dUL, 0x93b39e26UL, 0x187184c9UL, 0x6c00b32dUL, 0x73e2bb14UL,
0xa0bebc3cUL, 0x54623779UL, 0x64459eabUL, 0x3f328b82UL, 0x7718cf82UL, 0x59a2cea6UL,
0x04ee002eUL, 0x89fe78e6UL, 0x3fab0950UL, 0x325ff6c2UL, 0x81383f05UL, 0x6963c5c8UL,
0x76cb5ad6UL, 0xd49974c9UL, 0xca180dcfUL, 0x380782d5UL, 0xc7fa5cf6UL, 0x8ac31511UL,
0x35e79e13UL, 0x47da91d0UL, 0xf40f9086UL, 0xa7e2419eUL, 0x31366241UL, 0x051ef495UL,
0xaa573b04UL, 0x4a805d8dUL, 0x548300d0UL, 0x00322a3cUL, 0xbf64cddfUL, 0xba57a68eUL,
0x75c6372bUL, 0x50afd341UL, 0xa7c13275UL, 0x915a0bf5UL, 0x6b54bfabUL, 0x2b0b1426UL,
0xab4cc9d7UL, 0x449ccd82UL, 0xf7fbf265UL, 0xab85c5f3UL, 0x1b55db94UL, 0xaad4e324UL,
0xcfa4bd3fUL, 0x2deaa3e2UL, 0x9e204d02UL, 0xc8bd25acUL, 0xeadf55b3UL, 0xd5bd9e98UL,
0xe31231b2UL, 0x2ad5ad6cUL, 0x954329deUL, 0xadbe4528UL, 0xd8710f69UL, 0xaa51c90fUL,
0xaa786bf6UL, 0x22513f1eUL, 0xaa51a79bUL, 0x2ad344ccUL, 0x7b5a41f0UL, 0xd37cfbadUL,
0x1b069505UL, 0x41ece491UL, 0xb4c332e6UL, 0x032268d4UL, 0xc9600accUL, 0xce387e6dUL,
0xbf6bb16cUL, 0x6a70fb78UL, 0x0d03d9c9UL, 0xd4df39deUL, 0xe01063daUL, 0x4736f464UL,
0x5ad328d8UL, 0xb347cc96UL, 0x75bb0fc3UL, 0x98511bfbUL, 0x4ffbcc35UL, 0xb58bcf6aUL,
0xe11f0abcUL, 0xbfc5fe4aUL, 0xa70aec10UL, 0xac39570aUL, 0x3f04442fUL, 0x6188b153UL,
0xe0397a2eUL, 0x5727cb79UL, 0x9ceb418fUL, 0x1cacd68dUL, 0x2ad37c96UL, 0x0175cb9dUL,
0xc69dff09UL, 0xc75b65f0UL, 0xd9db40d8UL, 0xec0e7779UL, 0x4744ead4UL, 0xb11c3274UL,
0xdd24cb9eUL, 0x7e1c54bdUL, 0xf01144f9UL, 0xd2240eb1UL, 0x9675b3fdUL, 0xa3ac3755UL,
0xd47c27afUL, 0x51c85f4dUL, 0x56907596UL, 0xa5bb15e6UL, 0x580304f0UL, 0xca042cf1UL,
0x011a37eaUL, 0x8dbfaadbUL, 0x35ba3e4aUL, 0x3526ffa0UL, 0xc37b4d09UL, 0xbc306ed9UL,
0x98a52666UL, 0x5648f725UL, 0xff5e569dUL, 0x0ced63d0UL, 0x7c63b2cfUL, 0x700b45e1UL,
0xd5ea50f1UL, 0x85a92872UL, 0xaf1fbda7UL, 0xd4234870UL, 0xa7870bf3UL, 0x2d3b4d79UL,
0x42e04198UL, 0x0cd0ede7UL, 0x26470db8UL, 0xf881814cUL, 0x474d6ad7UL, 0x7c0c5e5cUL,
0xd1231959UL, 0x381b7298UL, 0xf5d2f4dbUL, 0xab838653UL, 0x6e2f1e23UL, 0x83719c9eUL,
0xbd91e046UL, 0x9a56456eUL, 0xdc39200cUL, 0x20c8c571UL, 0x962bda1cUL, 0xe1e696ffUL,
0xb141ab08UL, 0x7cca89b9UL, 0x1a69e783UL, 0x02cc4843UL, 0xa2f7c579UL, 0x429ef47dUL,
0x427b169cUL, 0x5ac9f049UL, 0xdd8f0f00UL, 0x5c8165bfUL};

static const ulong32 S2[256] = {
0x1f201094UL, 0xef0ba75bUL, 0x69e3cf7eUL, 0x393f4380UL, 0xfe61cf7aUL, 0xeec5207aUL,
0x55889c94UL, 0x72fc0651UL, 0xada7ef79UL, 0x4e1d7235UL, 0xd55a63ceUL, 0xde0436baUL,
0x99c430efUL, 0x5f0c0794UL, 0x18dcdb7dUL, 0xa1d6eff3UL, 0xa0b52f7bUL, 0x59e83605UL,
0xee15b094UL, 0xe9ffd909UL, 0xdc440086UL, 0xef944459UL, 0xba83ccb3UL, 0xe0c3cdfbUL,
0xd1da4181UL, 0x3b092ab1UL, 0xf997f1c1UL, 0xa5e6cf7bUL, 0x01420ddbUL, 0xe4e7ef5bUL,
0x25a1ff41UL, 0xe180f806UL, 0x1fc41080UL, 0x179bee7aUL, 0xd37ac6a9UL, 0xfe5830a4UL,
0x98de8b7fUL, 0x77e83f4eUL, 0x79929269UL, 0x24fa9f7bUL, 0xe113c85bUL, 0xacc40083UL,
0xd7503525UL, 0xf7ea615fUL, 0x62143154UL, 0x0d554b63UL, 0x5d681121UL, 0xc866c359UL,
0x3d63cf73UL, 0xcee234c0UL, 0xd4d87e87UL, 0x5c672b21UL, 0x071f6181UL, 0x39f7627fUL,
0x361e3084UL, 0xe4eb573bUL, 0x602f64a4UL, 0xd63acd9cUL, 0x1bbc4635UL, 0x9e81032dUL,
0x2701f50cUL, 0x99847ab4UL, 0xa0e3df79UL, 0xba6cf38cUL, 0x10843094UL, 0x2537a95eUL,
0xf46f6ffeUL, 0xa1ff3b1fUL, 0x208cfb6aUL, 0x8f458c74UL, 0xd9e0a227UL, 0x4ec73a34UL,
0xfc884f69UL, 0x3e4de8dfUL, 0xef0e0088UL, 0x3559648dUL, 0x8a45388cUL, 0x1d804366UL,
0x721d9bfdUL, 0xa58684bbUL, 0xe8256333UL, 0x844e8212UL, 0x128d8098UL, 0xfed33fb4UL,
0xce280ae1UL, 0x27e19ba5UL, 0xd5a6c252UL, 0xe49754bdUL, 0xc5d655ddUL, 0xeb667064UL,
0x77840b4dUL, 0xa1b6a801UL, 0x84db26a9UL, 0xe0b56714UL, 0x21f043b7UL, 0xe5d05860UL,
0x54f03084UL, 0x066ff472UL, 0xa31aa153UL, 0xdadc4755UL, 0xb5625dbfUL, 0x68561be6UL,
0x83ca6b94UL, 0x2d6ed23bUL, 0xeccf01dbUL, 0xa6d3d0baUL, 0xb6803d5cUL, 0xaf77a709UL,
0x33b4a34cUL, 0x397bc8d6UL, 0x5ee22b95UL, 0x5f0e5304UL, 0x81ed6f61UL, 0x20e74364UL,
0xb45e1378UL, 0xde18639bUL, 0x881ca122UL, 0xb96726d1UL, 0x8049a7e8UL, 0x22b7da7bUL,
0x5e552d25UL, 0x5272d237UL, 0x79d2951cUL, 0xc60d894cUL, 0x488cb402UL, 0x1ba4fe5bUL,
0xa4b09f6bUL, 0x1ca815cfUL, 0xa20c3005UL, 0x8871df63UL, 0xb9de2fcbUL, 0x0cc6c9e9UL,
0x0beeff53UL, 0xe3214517UL, 0xb4542835UL, 0x9f63293cUL, 0xee41e729UL, 0x6e1d2d7cUL,
0x50045286UL, 0x1e6685f3UL, 0xf33401c6UL, 0x30a22c95UL, 0x31a70850UL, 0x60930f13UL,
0x73f98417UL, 0xa1269859UL, 0xec645c44UL, 0x52c877a9UL, 0xcdff33a6UL, 0xa02b1741UL,
0x7cbad9a2UL, 0x2180036fUL, 0x50d99c08UL, 0xcb3f4861UL, 0xc26bd765UL, 0x64a3f6abUL,
0x80342676UL, 0x25a75e7bUL, 0xe4e6d1fcUL, 0x20c710e6UL, 0xcdf0b680UL, 0x17844d3bUL,
0x31eef84dUL, 0x7e0824e4UL, 0x2ccb49ebUL, 0x846a3baeUL, 0x8ff77888UL, 0xee5d60f6UL,
0x7af75673UL, 0x2fdd5cdbUL, 0xa11631c1UL, 0x30f66f43UL, 0xb3faec54UL, 0x157fd7faUL,
0xef8579ccUL, 0xd152de58UL, 0xdb2ffd5eUL, 0x8f32ce19UL, 0x306af97aUL, 0x02f03ef8UL,
0x99319ad5UL, 0xc242fa0fUL, 0xa7e3ebb0UL, 0xc68e4906UL, 0xb8da230cUL, 0x80823028UL,
0xdcdef3c8UL, 0xd35fb171UL, 0x088a1bc8UL, 0xbec0c560UL, 0x61a3c9e8UL, 0xbca8f54dUL,
0xc72feffaUL, 0x22822e99UL, 0x82c570b4UL, 0xd8d94e89UL, 0x8b1c34bcUL, 0x301e16e6UL,
0x273be979UL, 0xb0ffeaa6UL, 0x61d9b8c6UL, 0x00b24869UL, 0xb7ffce3fUL, 0x08dc283bUL,
0x43daf65aUL, 0xf7e19798UL, 0x7619b72fUL, 0x8f1c9ba4UL, 0xdc8637a0UL, 0x16a7d3b1UL,
0x9fc393b7UL, 0xa7136eebUL, 0xc6bcc63eUL, 0x1a513742UL, 0xef6828bcUL, 0x520365d6UL,
0x2d6a77abUL, 0x3527ed4bUL, 0x821fd216UL, 0x095c6e2eUL, 0xdb92f2fbUL, 0x5eea29cbUL,
0x145892f5UL, 0x91584f7fUL, 0x5483697bUL, 0x2667a8ccUL, 0x85196048UL, 0x8c4baceaUL,
0x833860d4UL, 0x0d23e0f9UL, 0x6c387e8aUL, 0x0ae6d249UL, 0xb284600cUL, 0xd835731dUL,
0xdcb1c647UL, 0xac4c56eaUL, 0x3ebd81b3UL, 0x230eabb0UL, 0x6438bc87UL, 0xf0b5b1faUL,
0x8f5ea2b3UL, 0xfc184642UL, 0x0a036b7aUL, 0x4fb089bdUL, 0x649da589UL, 0xa345415eUL,
0x5c038323UL, 0x3e5d3bb9UL, 0x43d79572UL, 0x7e6dd07cUL, 0x06dfdf1eUL, 0x6c6cc4efUL,
0x7160a539UL, 0x73bfbe70UL, 0x83877605UL, 0x4523ecf1UL};

static const ulong32 S3[256] = {
0x8defc240UL, 0x25fa5d9fUL, 0xeb903dbfUL, 0xe810c907UL, 0x47607fffUL, 0x369fe44bUL,
0x8c1fc644UL, 0xaececa90UL, 0xbeb1f9bfUL, 0xeefbcaeaUL, 0xe8cf1950UL, 0x51df07aeUL,
0x920e8806UL, 0xf0ad0548UL, 0xe13c8d83UL, 0x927010d5UL, 0x11107d9fUL, 0x07647db9UL,
0xb2e3e4d4UL, 0x3d4f285eUL, 0xb9afa820UL, 0xfade82e0UL, 0xa067268bUL, 0x8272792eUL,
0x553fb2c0UL, 0x489ae22bUL, 0xd4ef9794UL, 0x125e3fbcUL, 0x21fffceeUL, 0x825b1bfdUL,
0x9255c5edUL, 0x1257a240UL, 0x4e1a8302UL, 0xbae07fffUL, 0x528246e7UL, 0x8e57140eUL,
0x3373f7bfUL, 0x8c9f8188UL, 0xa6fc4ee8UL, 0xc982b5a5UL, 0xa8c01db7UL, 0x579fc264UL,
0x67094f31UL, 0xf2bd3f5fUL, 0x40fff7c1UL, 0x1fb78dfcUL, 0x8e6bd2c1UL, 0x437be59bUL,
0x99b03dbfUL, 0xb5dbc64bUL, 0x638dc0e6UL, 0x55819d99UL, 0xa197c81cUL, 0x4a012d6eUL,
0xc5884a28UL, 0xccc36f71UL, 0xb843c213UL, 0x6c0743f1UL, 0x8309893cUL, 0x0feddd5fUL,
0x2f7fe850UL, 0xd7c07f7eUL, 0x02507fbfUL, 0x5afb9a04UL, 0xa747d2d0UL, 0x1651192eUL,
0xaf70bf3eUL, 0x58c31380UL, 0x5f98302eUL, 0x727cc3c4UL, 0x0a0fb402UL, 0x0f7fef82UL,
0x8c96fdadUL, 0x5d2c2aaeUL, 0x8ee99a49UL, 0x50da88b8UL, 0x8427f4a0UL, 0x1eac5790UL,
0x796fb449UL, 0x8252dc15UL, 0xefbd7d9bUL, 0xa672597dUL, 0xada840d8UL, 0x45f54504UL,
0xfa5d7403UL, 0xe83ec305UL, 0x4f91751aUL, 0x925669c2UL, 0x23efe941UL, 0xa903f12eUL,
0x60270df2UL, 0x0276e4b6UL, 0x94fd6574UL, 0x927985b2UL, 0x8276dbcbUL, 0x02778176UL,
0xf8af918dUL, 0x4e48f79eUL, 0x8f616ddfUL, 0xe29d840eUL, 0x842f7d83UL, 0x340ce5c8UL,
0x96bbb682UL, 0x93b4b148UL, 0xef303cabUL, 0x984faf28UL, 0x779faf9bUL, 0x92dc560dUL,
0x224d1e20UL, 0x8437aa88UL, 0x7d29dc96UL, 0x2756d3dcUL, 0x8b907ceeUL, 0xb51fd240UL,
0xe7c07ce3UL, 0xe566b4a1UL, 0xc3e9615eUL, 0x3cf8209dUL, 0x6094d1e3UL, 0xcd9ca341UL,
0x5c76460eUL, 0x00ea983bUL, 0xd4d67881UL, 0xfd47572cUL, 0xf76cedd9UL, 0xbda8229cUL,
0x127dadaaUL, 0x438a074eUL, 0x1f97c090UL, 0x081bdb8aUL, 0x93a07ebeUL, 0xb938ca15UL,
0x97b03cffUL, 0x3dc2c0f8UL, 0x8d1ab2ecUL, 0x64380e51UL, 0x68cc7bfbUL, 0xd90f2788UL,
0x12490181UL, 0x5de5ffd4UL, 0xdd7ef86aUL, 0x76a2e214UL, 0xb9a40368UL, 0x925d958fUL,
0x4b39fffaUL, 0xba39aee9UL, 0xa4ffd30bUL, 0xfaf7933bUL, 0x6d498623UL, 0x193cbcfaUL,
0x27627545UL, 0x825cf47aUL, 0x61bd8ba0UL, 0xd11e42d1UL, 0xcead04f4UL, 0x127ea392UL,
0x10428db7UL, 0x8272a972UL, 0x9270c4a8UL, 0x127de50bUL, 0x285ba1c8UL, 0x3c62f44fUL,
0x35c0eaa5UL, 0xe805d231UL, 0x428929fbUL, 0xb4fcdf82UL, 0x4fb66a53UL, 0x0e7dc15bUL,
0x1f081fabUL, 0x108618aeUL, 0xfcfd086dUL, 0xf9ff2889UL, 0x694bcc11UL, 0x236a5caeUL,
0x12deca4dUL, 0x2c3f8cc5UL, 0xd2d02dfeUL, 0xf8ef5896UL, 0xe4cf52daUL, 0x95155b67UL,
0x494a488cUL, 0xb9b6a80cUL, 0x5c8f82bcUL, 0x89d36b45UL, 0x3a609437UL, 0xec00c9a9UL,
0x44715253UL, 0x0a874b49UL, 0xd773bc40UL, 0x7c34671cUL, 0x02717ef6UL, 0x4feb5536UL,
0xa2d02fffUL, 0xd2bf60c4UL, 0xd43f03c0UL, 0x50b4ef6dUL, 0x07478cd1UL, 0x006e1888UL,
0xa2e53f55UL, 0xb9e6d4bcUL, 0xa2048016UL, 0x97573833UL, 0xd7207d67UL, 0xde0f8f3dUL,
0x72f87b33UL, 0xabcc4f33UL, 0x7688c55dUL, 0x7b00a6b0UL, 0x947b0001UL, 0x570075d2UL,
0xf9bb88f8UL, 0x8942019eUL, 0x4264a5ffUL, 0x856302e0UL, 0x72dbd92bUL, 0xee971b69UL,
0x6ea22fdeUL, 0x5f08ae2bUL, 0xaf7a616dUL, 0xe5c98767UL, 0xcf1febd2UL, 0x61efc8c2UL,
0xf1ac2571UL, 0xcc8239c2UL, 0x67214cb8UL, 0xb1e583d1UL, 0xb7dc3e62UL, 0x7f10bdceUL,
0xf90a5c38UL, 0x0ff0443dUL, 0x606e6dc6UL, 0x60543a49UL, 0x5727c148UL, 0x2be98a1dUL,
0x8ab41738UL, 0x20e1be24UL, 0xaf96da0fUL, 0x68458425UL, 0x99833be5UL, 0x600d457dUL,
0x282f9350UL, 0x8334b362UL, 0xd91d1120UL, 0x2b6d8da0UL, 0x642b1e31UL, 0x9c305a00UL,
0x52bce688UL, 0x1b03588aUL, 0xf7baefd5UL, 0x4142ed9cUL, 0xa4315c11UL, 0x83323ec5UL,
0xdfef4636UL, 0xa133c501UL, 0xe9d3531cUL, 0xee353783UL};

static const ulong32 S4[256] = {
0x9db30420UL, 0x1fb6e9deUL, 0xa7be7befUL, 0xd273a298UL, 0x4a4f7bdbUL, 0x64ad8c57UL,
0x85510443UL, 0xfa020ed1UL, 0x7e287affUL, 0xe60fb663UL, 0x095f35a1UL, 0x79ebf120UL,
0xfd059d43UL, 0x6497b7b1UL, 0xf3641f63UL, 0x241e4adfUL, 0x28147f5fUL, 0x4fa2b8cdUL,
0xc9430040UL, 0x0cc32220UL, 0xfdd30b30UL, 0xc0a5374fUL, 0x1d2d00d9UL, 0x24147b15UL,
0xee4d111aUL, 0x0fca5167UL, 0x71ff904cUL, 0x2d195ffeUL, 0x1a05645fUL, 0x0c13fefeUL,
0x081b08caUL, 0x05170121UL, 0x80530100UL, 0xe83e5efeUL, 0xac9af4f8UL, 0x7fe72701UL,
0xd2b8ee5fUL, 0x06df4261UL, 0xbb9e9b8aUL, 0x7293ea25UL, 0xce84ffdfUL, 0xf5718801UL,
0x3dd64b04UL, 0xa26f263bUL, 0x7ed48400UL, 0x547eebe6UL, 0x446d4ca0UL, 0x6cf3d6f5UL,
0x2649abdfUL, 0xaea0c7f5UL, 0x36338cc1UL, 0x503f7e93UL, 0xd3772061UL, 0x11b638e1UL,
0x72500e03UL, 0xf80eb2bbUL, 0xabe0502eUL, 0xec8d77deUL, 0x57971e81UL, 0xe14f6746UL,
0xc9335400UL, 0x6920318fUL, 0x081dbb99UL, 0xffc304a5UL, 0x4d351805UL, 0x7f3d5ce3UL,
0xa6c866c6UL, 0x5d5bcca9UL, 0xdaec6feaUL, 0x9f926f91UL, 0x9f46222fUL, 0x3991467dUL,
0xa5bf6d8eUL, 0x1143c44fUL, 0x43958302UL, 0xd0214eebUL, 0x022083b8UL, 0x3fb6180cUL,
0x18f8931eUL, 0x281658e6UL, 0x26486e3eUL, 0x8bd78a70UL, 0x7477e4c1UL, 0xb506e07cUL,
0xf32d0a25UL, 0x79098b02UL, 0xe4eabb81UL, 0x28123b23UL, 0x69dead38UL, 0x1574ca16UL,
0xdf871b62UL, 0x211c40b7UL, 0xa51a9ef9UL, 0x0014377bUL, 0x041e8ac8UL, 0x09114003UL,
0xbd59e4d2UL, 0xe3d156d5UL, 0x4fe876d5UL, 0x2f91a340UL, 0x557be8deUL, 0x00eae4a7UL,
0x0ce5c2ecUL, 0x4db4bba6UL, 0xe756bdffUL, 0xdd3369acUL, 0xec17b035UL, 0x06572327UL,
0x99afc8b0UL, 0x56c8c391UL, 0x6b65811cUL, 0x5e146119UL, 0x6e85cb75UL, 0xbe07c002UL,
0xc2325577UL, 0x893ff4ecUL, 0x5bbfc92dUL, 0xd0ec3b25UL, 0xb7801ab7UL, 0x8d6d3b24UL,
0x20c763efUL, 0xc366a5fcUL, 0x9c382880UL, 0x0ace3205UL, 0xaac9548aUL, 0xeca1d7c7UL,
0x041afa32UL, 0x1d16625aUL, 0x6701902cUL, 0x9b757a54UL, 0x31d477f7UL, 0x9126b031UL,
0x36cc6fdbUL, 0xc70b8b46UL, 0xd9e66a48UL, 0x56e55a79UL, 0x026a4cebUL, 0x52437effUL,
0x2f8f76b4UL, 0x0df980a5UL, 0x8674cde3UL, 0xedda04ebUL, 0x17a9be04UL, 0x2c18f4dfUL,
0xb7747f9dUL, 0xab2af7b4UL, 0xefc34d20UL, 0x2e096b7cUL, 0x1741a254UL, 0xe5b6a035UL,
0x213d42f6UL, 0x2c1c7c26UL, 0x61c2f50fUL, 0x6552daf9UL, 0xd2c231f8UL, 0x25130f69UL,
0xd8167fa2UL, 0x0418f2c8UL, 0x001a96a6UL, 0x0d1526abUL, 0x63315c21UL, 0x5e0a72ecUL,
0x49bafefdUL, 0x187908d9UL, 0x8d0dbd86UL, 0x311170a7UL, 0x3e9b640cUL, 0xcc3e10d7UL,
0xd5cad3b6UL, 0x0caec388UL, 0xf73001e1UL, 0x6c728affUL, 0x71eae2a1UL, 0x1f9af36eUL,
0xcfcbd12fUL, 0xc1de8417UL, 0xac07be6bUL, 0xcb44a1d8UL, 0x8b9b0f56UL, 0x013988c3UL,
0xb1c52fcaUL, 0xb4be31cdUL, 0xd8782806UL, 0x12a3a4e2UL, 0x6f7de532UL, 0x58fd7eb6UL,
0xd01ee900UL, 0x24adffc2UL, 0xf4990fc5UL, 0x9711aac5UL, 0x001d7b95UL, 0x82e5e7d2UL,
0x109873f6UL, 0x00613096UL, 0xc32d9521UL, 0xada121ffUL, 0x29908415UL, 0x7fbb977fUL,
0xaf9eb3dbUL, 0x29c9ed2aUL, 0x5ce2a465UL, 0xa730f32cUL, 0xd0aa3fe8UL, 0x8a5cc091UL,
0xd49e2ce7UL, 0x0ce454a9UL, 0xd60acd86UL, 0x015f1919UL, 0x77079103UL, 0xdea03af6UL,
0x78a8565eUL, 0xdee356dfUL, 0x21f05cbeUL, 0x8b75e387UL, 0xb3c50651UL, 0xb8a5c3efUL,
0xd8eeb6d2UL, 0xe523be77UL, 0xc2154529UL, 0x2f69efdfUL, 0xafe67afbUL, 0xf470c4b2UL,
0xf3e0eb5bUL, 0xd6cc9876UL, 0x39e4460cUL, 0x1fda8538UL, 0x1987832fUL, 0xca007367UL,
0xa99144f8UL, 0x296b299eUL, 0x492fc295UL, 0x9266beabUL, 0xb5676e69UL, 0x9bd3dddaUL,
0xdf7e052fUL, 0xdb25701cUL, 0x1b5e51eeUL, 0xf65324e6UL, 0x6afce36cUL, 0x0316cc04UL,
0x8644213eUL, 0xb7dc59d0UL, 0x7965291fUL, 0xccd6fd43UL, 0x41823979UL, 0x932bcdf6UL,
0xb657c34dUL, 0x4edfd282UL, 0x7ae5290cUL, 0x3cb9536bUL, 0x851e20feUL, 0x9833557eUL,
0x13ecf0b0UL, 0xd3ffb372UL, 0x3f85c5c1UL, 0x0aef7ed2UL};

static const ulong32 S5[256] = {
0x7ec90c04UL, 0x2c6e74b9UL, 0x9b0e66dfUL, 0xa6337911UL, 0xb86a7fffUL, 0x1dd358f5UL,
0x44dd9d44UL, 0x1731167fUL, 0x08fbf1faUL, 0xe7f511ccUL, 0xd2051b00UL, 0x735aba00UL,
0x2ab722d8UL, 0x386381cbUL, 0xacf6243aUL, 0x69befd7aUL, 0xe6a2e77fUL, 0xf0c720cdUL,
0xc4494816UL, 0xccf5c180UL, 0x38851640UL, 0x15b0a848UL, 0xe68b18cbUL, 0x4caadeffUL,
0x5f480a01UL, 0x0412b2aaUL, 0x259814fcUL, 0x41d0efe2UL, 0x4e40b48dUL, 0x248eb6fbUL,
0x8dba1cfeUL, 0x41a99b02UL, 0x1a550a04UL, 0xba8f65cbUL, 0x7251f4e7UL, 0x95a51725UL,
0xc106ecd7UL, 0x97a5980aUL, 0xc539b9aaUL, 0x4d79fe6aUL, 0xf2f3f763UL, 0x68af8040UL,
0xed0c9e56UL, 0x11b4958bUL, 0xe1eb5a88UL, 0x8709e6b0UL, 0xd7e07156UL, 0x4e29fea7UL,
0x6366e52dUL, 0x02d1c000UL, 0xc4ac8e05UL, 0x9377f571UL, 0x0c05372aUL, 0x578535f2UL,
0x2261be02UL, 0xd642a0c9UL, 0xdf13a280UL, 0x74b55bd2UL, 0x682199c0UL, 0xd421e5ecUL,
0x53fb3ce8UL, 0xc8adedb3UL, 0x28a87fc9UL, 0x3d959981UL, 0x5c1ff900UL, 0xfe38d399UL,
0x0c4eff0bUL, 0x062407eaUL, 0xaa2f4fb1UL, 0x4fb96976UL, 0x90c79505UL, 0xb0a8a774UL,
0xef55a1ffUL, 0xe59ca2c2UL, 0xa6b62d27UL, 0xe66a4263UL, 0xdf65001fUL, 0x0ec50966UL,
0xdfdd55bcUL, 0x29de0655UL, 0x911e739aUL, 0x17af8975UL, 0x32c7911cUL, 0x89f89468UL,
0x0d01e980UL, 0x524755f4UL, 0x03b63cc9UL, 0x0cc844b2UL, 0xbcf3f0aaUL, 0x87ac36e9UL,
0xe53a7426UL, 0x01b3d82bUL, 0x1a9e7449UL, 0x64ee2d7eUL, 0xcddbb1daUL, 0x01c94910UL,
0xb868bf80UL, 0x0d26f3fdUL, 0x9342ede7UL, 0x04a5c284UL, 0x636737b6UL, 0x50f5b616UL,
0xf24766e3UL, 0x8eca36c1UL, 0x136e05dbUL, 0xfef18391UL, 0xfb887a37UL, 0xd6e7f7d4UL,
0xc7fb7dc9UL, 0x3063fcdfUL, 0xb6f589deUL, 0xec2941daUL, 0x26e46695UL, 0xb7566419UL,
0xf654efc5UL, 0xd08d58b7UL, 0x48925401UL, 0xc1bacb7fUL, 0xe5ff550fUL, 0xb6083049UL,
0x5bb5d0e8UL, 0x87d72e5aUL, 0xab6a6ee1UL, 0x223a66ceUL, 0xc62bf3cdUL, 0x9e0885f9UL,
0x68cb3e47UL, 0x086c010fUL, 0xa21de820UL, 0xd18b69deUL, 0xf3f65777UL, 0xfa02c3f6UL,
0x407edac3UL, 0xcbb3d550UL, 0x1793084dUL, 0xb0d70ebaUL, 0x0ab378d5UL, 0xd951fb0cUL,
0xded7da56UL, 0x4124bbe4UL, 0x94ca0b56UL, 0x0f5755d1UL, 0xe0e1e56eUL, 0x6184b5beUL,
0x580a249fUL, 0x94f74bc0UL, 0xe327888eUL, 0x9f7b5561UL, 0xc3dc0280UL, 0x05687715UL,
0x646c6bd7UL, 0x44904db3UL, 0x66b4f0a3UL, 0xc0f1648aUL, 0x697ed5afUL, 0x49e92ff6UL,
0x309e374fUL, 0x2cb6356aUL, 0x85808573UL, 0x4991f840UL, 0x76f0ae02UL, 0x083be84dUL,
0x28421c9aUL, 0x44489406UL, 0x736e4cb8UL, 0xc1092910UL, 0x8bc95fc6UL, 0x7d869cf4UL,
0x134f616fUL, 0x2e77118dUL, 0xb31b2be1UL, 0xaa90b472UL, 0x3ca5d717UL, 0x7d161bbaUL,
0x9cad9010UL, 0xaf462ba2UL, 0x9fe459d2UL, 0x45d34559UL, 0xd9f2da13UL, 0xdbc65487UL,
0xf3e4f94eUL, 0x176d486fUL, 0x097c13eaUL, 0x631da5c7UL, 0x445f7382UL, 0x175683f4UL,
0xcdc66a97UL, 0x70be0288UL, 0xb3cdcf72UL, 0x6e5dd2f3UL, 0x20936079UL, 0x459b80a5UL,
0xbe60e2dbUL, 0xa9c23101UL, 0xeba5315cUL, 0x224e42f2UL, 0x1c5c1572UL, 0xf6721b2cUL,
0x1ad2fff3UL, 0x8c25404eUL, 0x324ed72fUL, 0x4067b7fdUL, 0x0523138eUL, 0x5ca3bc78UL,
0xdc0fd66eUL, 0x75922283UL, 0x784d6b17UL, 0x58ebb16eUL, 0x44094f85UL, 0x3f481d87UL,
0xfcfeae7bUL, 0x77b5ff76UL, 0x8c2302bfUL, 0xaaf47556UL, 0x5f46b02aUL, 0x2b092801UL,
0x3d38f5f7UL, 0x0ca81f36UL, 0x52af4a8aUL, 0x66d5e7c0UL, 0xdf3b0874UL, 0x95055110UL,
0x1b5ad7a8UL, 0xf61ed5adUL, 0x6cf6e479UL, 0x20758184UL, 0xd0cefa65UL, 0x88f7be58UL,
0x4a046826UL, 0x0ff6f8f3UL, 0xa09c7f70UL, 0x5346aba0UL, 0x5ce96c28UL, 0xe176eda3UL,
0x6bac307fUL, 0x376829d2UL, 0x85360fa9UL, 0x17e3fe2aUL, 0x24b79767UL, 0xf5a96b20UL,
0xd6cd2595UL, 0x68ff1ebfUL, 0x7555442cUL, 0xf19f06beUL, 0xf9e0659aUL, 0xeeb9491dUL,
0x34010718UL, 0xbb30cab8UL, 0xe822fe15UL, 0x88570983UL, 0x750e6249UL, 0xda627e55UL,
0x5e76ffa8UL, 0xb1534546UL, 0x6d47de08UL, 0xefe9e7d4UL};

static const ulong32 S6[256] = {
0xf6fa8f9dUL, 0x2cac6ce1UL, 0x4ca34867UL, 0xe2337f7cUL, 0x95db08e7UL, 0x016843b4UL,
0xeced5cbcUL, 0x325553acUL, 0xbf9f0960UL, 0xdfa1e2edUL, 0x83f0579dUL, 0x63ed86b9UL,
0x1ab6a6b8UL, 0xde5ebe39UL, 0xf38ff732UL, 0x8989b138UL, 0x33f14961UL, 0xc01937bdUL,
0xf506c6daUL, 0xe4625e7eUL, 0xa308ea99UL, 0x4e23e33cUL, 0x79cbd7ccUL, 0x48a14367UL,
0xa3149619UL, 0xfec94bd5UL, 0xa114174aUL, 0xeaa01866UL, 0xa084db2dUL, 0x09a8486fUL,
0xa888614aUL, 0x2900af98UL, 0x01665991UL, 0xe1992863UL, 0xc8f30c60UL, 0x2e78ef3cUL,
0xd0d51932UL, 0xcf0fec14UL, 0xf7ca07d2UL, 0xd0a82072UL, 0xfd41197eUL, 0x9305a6b0UL,
0xe86be3daUL, 0x74bed3cdUL, 0x372da53cUL, 0x4c7f4448UL, 0xdab5d440UL, 0x6dba0ec3UL,
0x083919a7UL, 0x9fbaeed9UL, 0x49dbcfb0UL, 0x4e670c53UL, 0x5c3d9c01UL, 0x64bdb941UL,
0x2c0e636aUL, 0xba7dd9cdUL, 0xea6f7388UL, 0xe70bc762UL, 0x35f29adbUL, 0x5c4cdd8dUL,
0xf0d48d8cUL, 0xb88153e2UL, 0x08a19866UL, 0x1ae2eac8UL, 0x284caf89UL, 0xaa928223UL,
0x9334be53UL, 0x3b3a21bfUL, 0x16434be3UL, 0x9aea3906UL, 0xefe8c36eUL, 0xf890cdd9UL,
0x80226daeUL, 0xc340a4a3UL, 0xdf7e9c09UL, 0xa694a807UL, 0x5b7c5eccUL, 0x221db3a6UL,
0x9a69a02fUL, 0x68818a54UL, 0xceb2296fUL, 0x53c0843aUL, 0xfe893655UL, 0x25bfe68aUL,
0xb4628abcUL, 0xcf222ebfUL, 0x25ac6f48UL, 0xa9a99387UL, 0x53bddb65UL, 0xe76ffbe7UL,
0xe967fd78UL, 0x0ba93563UL, 0x8e342bc1UL, 0xe8a11be9UL, 0x4980740dUL, 0xc8087dfcUL,
0x8de4bf99UL, 0xa11101a0UL, 0x7fd37975UL, 0xda5a26c0UL, 0xe81f994fUL, 0x9528cd89UL,
0xfd339fedUL, 0xb87834bfUL, 0x5f04456dUL, 0x22258698UL, 0xc9c4c83bUL, 0x2dc156beUL,
0x4f628daaUL, 0x57f55ec5UL, 0xe2220abeUL, 0xd2916ebfUL, 0x4ec75b95UL, 0x24f2c3c0UL,
0x42d15d99UL, 0xcd0d7fa0UL, 0x7b6e27ffUL, 0xa8dc8af0UL, 0x7345c106UL, 0xf41e232fUL,
0x35162386UL, 0xe6ea8926UL, 0x3333b094UL, 0x157ec6f2UL, 0x372b74afUL, 0x692573e4UL,
0xe9a9d848UL, 0xf3160289UL, 0x3a62ef1dUL, 0xa787e238UL, 0xf3a5f676UL, 0x74364853UL,
0x20951063UL, 0x4576698dUL, 0xb6fad407UL, 0x592af950UL, 0x36f73523UL, 0x4cfb6e87UL,
0x7da4cec0UL, 0x6c152daaUL, 0xcb0396a8UL, 0xc50dfe5dUL, 0xfcd707abUL, 0x0921c42fUL,
0x89dff0bbUL, 0x5fe2be78UL, 0x448f4f33UL, 0x754613c9UL, 0x2b05d08dUL, 0x48b9d585UL,
0xdc049441UL, 0xc8098f9bUL, 0x7dede786UL, 0xc39a3373UL, 0x42410005UL, 0x6a091751UL,
0x0ef3c8a6UL, 0x890072d6UL, 0x28207682UL, 0xa9a9f7beUL, 0xbf32679dUL, 0xd45b5b75UL,
0xb353fd00UL, 0xcbb0e358UL, 0x830f220aUL, 0x1f8fb214UL, 0xd372cf08UL, 0xcc3c4a13UL,
0x8cf63166UL, 0x061c87beUL, 0x88c98f88UL, 0x6062e397UL, 0x47cf8e7aUL, 0xb6c85283UL,
0x3cc2acfbUL, 0x3fc06976UL, 0x4e8f0252UL, 0x64d8314dUL, 0xda3870e3UL, 0x1e665459UL,
0xc10908f0UL, 0x513021a5UL, 0x6c5b68b7UL, 0x822f8aa0UL, 0x3007cd3eUL, 0x74719eefUL,
0xdc872681UL, 0x073340d4UL, 0x7e432fd9UL, 0x0c5ec241UL, 0x8809286cUL, 0xf592d891UL,
0x08a930f6UL, 0x957ef305UL, 0xb7fbffbdUL, 0xc266e96fUL, 0x6fe4ac98UL, 0xb173ecc0UL,
0xbc60b42aUL, 0x953498daUL, 0xfba1ae12UL, 0x2d4bd736UL, 0x0f25faabUL, 0xa4f3fcebUL,
0xe2969123UL, 0x257f0c3dUL, 0x9348af49UL, 0x361400bcUL, 0xe8816f4aUL, 0x3814f200UL,
0xa3f94043UL, 0x9c7a54c2UL, 0xbc704f57UL, 0xda41e7f9UL, 0xc25ad33aUL, 0x54f4a084UL,
0xb17f5505UL, 0x59357cbeUL, 0xedbd15c8UL, 0x7f97c5abUL, 0xba5ac7b5UL, 0xb6f6deafUL,
0x3a479c3aUL, 0x5302da25UL, 0x653d7e6aUL, 0x54268d49UL, 0x51a477eaUL, 0x5017d55bUL,
0xd7d25d88UL, 0x44136c76UL, 0x0404a8c8UL, 0xb8e5a121UL, 0xb81a928aUL, 0x60ed5869UL,
0x97c55b96UL, 0xeaec991bUL, 0x29935913UL, 0x01fdb7f1UL, 0x088e8dfaUL, 0x9ab6f6f5UL,
0x3b4cbf9fUL, 0x4a5de3abUL, 0xe6051d35UL, 0xa0e1d855UL, 0xd36b4cf1UL, 0xf544edebUL,
0xb0e93524UL, 0xbebb8fbdUL, 0xa2d762cfUL, 0x49c92f54UL, 0x38b5f331UL, 0x7128a454UL,
0x48392905UL, 0xa65b1db8UL, 0x851c97bdUL, 0xd675cf2fUL};

static const ulong32 S7[256] = {
0x85e04019UL, 0x332bf567UL, 0x662dbfffUL, 0xcfc65693UL, 0x2a8d7f6fUL, 0xab9bc912UL,
0xde6008a1UL, 0x2028da1fUL, 0x0227bce7UL, 0x4d642916UL, 0x18fac300UL, 0x50f18b82UL,
0x2cb2cb11UL, 0xb232e75cUL, 0x4b3695f2UL, 0xb28707deUL, 0xa05fbcf6UL, 0xcd4181e9UL,
0xe150210cUL, 0xe24ef1bdUL, 0xb168c381UL, 0xfde4e789UL, 0x5c79b0d8UL, 0x1e8bfd43UL,
0x4d495001UL, 0x38be4341UL, 0x913cee1dUL, 0x92a79c3fUL, 0x089766beUL, 0xbaeeadf4UL,
0x1286becfUL, 0xb6eacb19UL, 0x2660c200UL, 0x7565bde4UL, 0x64241f7aUL, 0x8248dca9UL,
0xc3b3ad66UL, 0x28136086UL, 0x0bd8dfa8UL, 0x356d1cf2UL, 0x107789beUL, 0xb3b2e9ceUL,
0x0502aa8fUL, 0x0bc0351eUL, 0x166bf52aUL, 0xeb12ff82UL, 0xe3486911UL, 0xd34d7516UL,
0x4e7b3affUL, 0x5f43671bUL, 0x9cf6e037UL, 0x4981ac83UL, 0x334266ceUL, 0x8c9341b7UL,
0xd0d854c0UL, 0xcb3a6c88UL, 0x47bc2829UL, 0x4725ba37UL, 0xa66ad22bUL, 0x7ad61f1eUL,
0x0c5cbafaUL, 0x4437f107UL, 0xb6e79962UL, 0x42d2d816UL, 0x0a961288UL, 0xe1a5c06eUL,
0x13749e67UL, 0x72fc081aUL, 0xb1d139f7UL, 0xf9583745UL, 0xcf19df58UL, 0xbec3f756UL,
0xc06eba30UL, 0x07211b24UL, 0x45c28829UL, 0xc95e317fUL, 0xbc8ec511UL, 0x38bc46e9UL,
0xc6e6fa14UL, 0xbae8584aUL, 0xad4ebc46UL, 0x468f508bUL, 0x7829435fUL, 0xf124183bUL,
0x821dba9fUL, 0xaff60ff4UL, 0xea2c4e6dUL, 0x16e39264UL, 0x92544a8bUL, 0x009b4fc3UL,
0xaba68cedUL, 0x9ac96f78UL, 0x06a5b79aUL, 0xb2856e6eUL, 0x1aec3ca9UL, 0xbe838688UL,
0x0e0804e9UL, 0x55f1be56UL, 0xe7e5363bUL, 0xb3a1f25dUL, 0xf7debb85UL, 0x61fe033cUL,
0x16746233UL, 0x3c034c28UL, 0xda6d0c74UL, 0x79aac56cUL, 0x3ce4e1adUL, 0x51f0c802UL,
0x98f8f35aUL, 0x1626a49fUL, 0xeed82b29UL, 0x1d382fe3UL, 0x0c4fb99aUL, 0xbb325778UL,
0x3ec6d97bUL, 0x6e77a6a9UL, 0xcb658b5cUL, 0xd45230c7UL, 0x2bd1408bUL, 0x60c03eb7UL,
0xb9068d78UL, 0xa33754f4UL, 0xf430c87dUL, 0xc8a71302UL, 0xb96d8c32UL, 0xebd4e7beUL,
0xbe8b9d2dUL, 0x7979fb06UL, 0xe7225308UL, 0x8b75cf77UL, 0x11ef8da4UL, 0xe083c858UL,
0x8d6b786fUL, 0x5a6317a6UL, 0xfa5cf7a0UL, 0x5dda0033UL, 0xf28ebfb0UL, 0xf5b9c310UL,
0xa0eac280UL, 0x08b9767aUL, 0xa3d9d2b0UL, 0x79d34217UL, 0x021a718dUL, 0x9ac6336aUL,
0x2711fd60UL, 0x438050e3UL, 0x069908a8UL, 0x3d7fedc4UL, 0x826d2befUL, 0x4eeb8476UL,
0x488dcf25UL, 0x36c9d566UL, 0x28e74e41UL, 0xc2610acaUL, 0x3d49a9cfUL, 0xbae3b9dfUL,
0xb65f8de6UL, 0x92aeaf64UL, 0x3ac7d5e6UL, 0x9ea80509UL, 0xf22b017dUL, 0xa4173f70UL,
0xdd1e16c3UL, 0x15e0d7f9UL, 0x50b1b887UL, 0x2b9f4fd5UL, 0x625aba82UL, 0x6a017962UL,
0x2ec01b9cUL, 0x15488aa9UL, 0xd716e740UL, 0x40055a2cUL, 0x93d29a22UL, 0xe32dbf9aUL,
0x058745b9UL, 0x3453dc1eUL, 0xd699296eUL, 0x496cff6fUL, 0x1c9f4986UL, 0xdfe2ed07UL,
0xb87242d1UL, 0x19de7eaeUL, 0x053e561aUL, 0x15ad6f8cUL, 0x66626c1cUL, 0x7154c24cUL,
0xea082b2aUL, 0x93eb2939UL, 0x17dcb0f0UL, 0x58d4f2aeUL, 0x9ea294fbUL, 0x52cf564cUL,
0x9883fe66UL, 0x2ec40581UL, 0x763953c3UL, 0x01d6692eUL, 0xd3a0c108UL, 0xa1e7160eUL,
0xe4f2dfa6UL, 0x693ed285UL, 0x74904698UL, 0x4c2b0eddUL, 0x4f757656UL, 0x5d393378UL,
0xa132234fUL, 0x3d321c5dUL, 0xc3f5e194UL, 0x4b269301UL, 0xc79f022fUL, 0x3c997e7eUL,
0x5e4f9504UL, 0x3ffafbbdUL, 0x76f7ad0eUL, 0x296693f4UL, 0x3d1fce6fUL, 0xc61e45beUL,
0xd3b5ab34UL, 0xf72bf9b7UL, 0x1b0434c0UL, 0x4e72b567UL, 0x5592a33dUL, 0xb5229301UL,
0xcfd2a87fUL, 0x60aeb767UL, 0x1814386bUL, 0x30bcc33dUL, 0x38a0c07dUL, 0xfd1606f2UL,
0xc363519bUL, 0x589dd390UL, 0x5479f8e6UL, 0x1cb8d647UL, 0x97fd61a9UL, 0xea7759f4UL,
0x2d57539dUL, 0x569a58cfUL, 0xe84e63adUL, 0x462e1b78UL, 0x6580f87eUL, 0xf3817914UL,
0x91da55f4UL, 0x40a230f3UL, 0xd1988f35UL, 0xb6e318d2UL, 0x3ffa50bcUL, 0x3d40f021UL,
0xc3c0bdaeUL, 0x4958c24cUL, 0x518f36b2UL, 0x84b1d370UL, 0x0fedce83UL, 0x878ddadaUL,
0xf2a279c7UL, 0x94e01be8UL, 0x90716f4bUL, 0x954b8aa3UL};

static const ulong32 S8[256] = {
0xe216300dUL, 0xbbddfffcUL, 0xa7ebdabdUL, 0x35648095UL, 0x7789f8b7UL, 0xe6c1121bUL,
0x0e241600UL, 0x052ce8b5UL, 0x11a9cfb0UL, 0xe5952f11UL, 0xece7990aUL, 0x9386d174UL,
0x2a42931cUL, 0x76e38111UL, 0xb12def3aUL, 0x37ddddfcUL, 0xde9adeb1UL, 0x0a0cc32cUL,
0xbe197029UL, 0x84a00940UL, 0xbb243a0fUL, 0xb4d137cfUL, 0xb44e79f0UL, 0x049eedfdUL,
0x0b15a15dUL, 0x480d3168UL, 0x8bbbde5aUL, 0x669ded42UL, 0xc7ece831UL, 0x3f8f95e7UL,
0x72df191bUL, 0x7580330dUL, 0x94074251UL, 0x5c7dcdfaUL, 0xabbe6d63UL, 0xaa402164UL,
0xb301d40aUL, 0x02e7d1caUL, 0x53571daeUL, 0x7a3182a2UL, 0x12a8ddecUL, 0xfdaa335dUL,
0x176f43e8UL, 0x71fb46d4UL, 0x38129022UL, 0xce949ad4UL, 0xb84769adUL, 0x965bd862UL,
0x82f3d055UL, 0x66fb9767UL, 0x15b80b4eUL, 0x1d5b47a0UL, 0x4cfde06fUL, 0xc28ec4b8UL,
0x57e8726eUL, 0x647a78fcUL, 0x99865d44UL, 0x608bd593UL, 0x6c200e03UL, 0x39dc5ff6UL,
0x5d0b00a3UL, 0xae63aff2UL, 0x7e8bd632UL, 0x70108c0cUL, 0xbbd35049UL, 0x2998df04UL,
0x980cf42aUL, 0x9b6df491UL, 0x9e7edd53UL, 0x06918548UL, 0x58cb7e07UL, 0x3b74ef2eUL,
0x522fffb1UL, 0xd24708ccUL, 0x1c7e27cdUL, 0xa4eb215bUL, 0x3cf1d2e2UL, 0x19b47a38UL,
0x424f7618UL, 0x35856039UL, 0x9d17dee7UL, 0x27eb35e6UL, 0xc9aff67bUL, 0x36baf5b8UL,
0x09c467cdUL, 0xc18910b1UL, 0xe11dbf7bUL, 0x06cd1af8UL, 0x7170c608UL, 0x2d5e3354UL,
0xd4de495aUL, 0x64c6d006UL, 0xbcc0c62cUL, 0x3dd00db3UL, 0x708f8f34UL, 0x77d51b42UL,
0x264f620fUL, 0x24b8d2bfUL, 0x15c1b79eUL, 0x46a52564UL, 0xf8d7e54eUL, 0x3e378160UL,
0x7895cda5UL, 0x859c15a5UL, 0xe6459788UL, 0xc37bc75fUL, 0xdb07ba0cUL, 0x0676a3abUL,
0x7f229b1eUL, 0x31842e7bUL, 0x24259fd7UL, 0xf8bef472UL, 0x835ffcb8UL, 0x6df4c1f2UL,
0x96f5b195UL, 0xfd0af0fcUL, 0xb0fe134cUL, 0xe2506d3dUL, 0x4f9b12eaUL, 0xf215f225UL,
0xa223736fUL, 0x9fb4c428UL, 0x25d04979UL, 0x34c713f8UL, 0xc4618187UL, 0xea7a6e98UL,
0x7cd16efcUL, 0x1436876cUL, 0xf1544107UL, 0xbedeee14UL, 0x56e9af27UL, 0xa04aa441UL,
0x3cf7c899UL, 0x92ecbae6UL, 0xdd67016dUL, 0x151682ebUL, 0xa842eedfUL, 0xfdba60b4UL,
0xf1907b75UL, 0x20e3030fUL, 0x24d8c29eUL, 0xe139673bUL, 0xefa63fb8UL, 0x71873054UL,
0xb6f2cf3bUL, 0x9f326442UL, 0xcb15a4ccUL, 0xb01a4504UL, 0xf1e47d8dUL, 0x844a1be5UL,
0xbae7dfdcUL, 0x42cbda70UL, 0xcd7dae0aUL, 0x57e85b7aUL, 0xd53f5af6UL, 0x20cf4d8cUL,
0xcea4d428UL, 0x79d130a4UL, 0x3486ebfbUL, 0x33d3cddcUL, 0x77853b53UL, 0x37effcb5UL,
0xc5068778UL, 0xe580b3e6UL, 0x4e68b8f4UL, 0xc5c8b37eUL, 0x0d809ea2UL, 0x398feb7cUL,
0x132a4f94UL, 0x43b7950eUL, 0x2fee7d1cUL, 0x223613bdUL, 0xdd06caa2UL, 0x37df932bUL,
0xc4248289UL, 0xacf3ebc3UL, 0x5715f6b7UL, 0xef3478ddUL, 0xf267616fUL, 0xc148cbe4UL,
0x9052815eUL, 0x5e410fabUL, 0xb48a2465UL, 0x2eda7fa4UL, 0xe87b40e4UL, 0xe98ea084UL,
0x5889e9e1UL, 0xefd390fcUL, 0xdd07d35bUL, 0xdb485694UL, 0x38d7e5b2UL, 0x57720101UL,
0x730edebcUL, 0x5b643113UL, 0x94917e4fUL, 0x503c2fbaUL, 0x646f1282UL, 0x7523d24aUL,
0xe0779695UL, 0xf9c17a8fUL, 0x7a5b2121UL, 0xd187b896UL, 0x29263a4dUL, 0xba510cdfUL,
0x81f47c9fUL, 0xad1163edUL, 0xea7b5965UL, 0x1a00726eUL, 0x11403092UL, 0x00da6d77UL,
0x4a0cdd61UL, 0xad1f4603UL, 0x605bdfb0UL, 0x9eedc364UL, 0x22ebe6a8UL, 0xcee7d28aUL,
0xa0e736a0UL, 0x5564a6b9UL, 0x10853209UL, 0xc7eb8f37UL, 0x2de705caUL, 0x8951570fUL,
0xdf09822bUL, 0xbd691a6cUL, 0xaa12e4f2UL, 0x87451c0fUL, 0xe0f6a27aUL, 0x3ada4819UL,
0x4cf1764fUL, 0x0d771c2bUL, 0x67cdb156UL, 0x350d8384UL, 0x5938fa0fUL, 0x42399ef3UL,
0x36997b07UL, 0x0e84093dUL, 0x4aa93e61UL, 0x8360d87bUL, 0x1fa98b0cUL, 0x1149382cUL,
0xe97625a5UL, 0x0614d1b7UL, 0x0e25244bUL, 0x0c768347UL, 0x589e8d82UL, 0x0d2059d1UL,
0xa466bb1eUL, 0xf8da0a82UL, 0x04f19130UL, 0xba6e4ec0UL, 0x99265164UL, 0x1ee7230dUL,
0x50b2ad80UL, 0xeaee6801UL, 0x8db2a283UL, 0xea8bf59eUL};


#define GB(x, i) (((x[(15-i)>>2])>>(unsigned)(8*((15-i)&3)))&255)


int cast5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey){
   ulong32 x[4], z[4];
   unsigned char buf[16];
   int y, i;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 12 && num_rounds != 16 && num_rounds != 0) {
      return CRYPT_INVALID_ROUNDS;
   }

   if (num_rounds == 12 && keylen > 10) {
      return CRYPT_INVALID_ROUNDS;
   }

   if (keylen < 5 || keylen > 16) {
      return CRYPT_INVALID_KEYSIZE;
   }

   /* extend the key as required */
   zeromem(buf, sizeof(buf));
   XMEMCPY(buf, key, (size_t)keylen);

   /* load and start the awful looking network */
   for (y = 0; y < 4; y++) {
       LOAD32H(x[3-y],buf+4*y);
   }

   for (i = y = 0; y < 2; y++) {
        z[3] = x[3] ^ S5[GB(x, 0xD)] ^ S6[GB(x, 0xF)] ^ S7[GB(x, 0xC)] ^ S8[GB(x, 0xE)] ^ S7[GB(x, 0x8)];
        z[2] = x[1] ^ S5[GB(z, 0x0)] ^ S6[GB(z, 0x2)] ^ S7[GB(z, 0x1)] ^ S8[GB(z, 0x3)] ^ S8[GB(x, 0xA)];
        z[1] = x[0] ^ S5[GB(z, 0x7)] ^ S6[GB(z, 0x6)] ^ S7[GB(z, 0x5)] ^ S8[GB(z, 0x4)] ^ S5[GB(x, 0x9)];
        z[0] = x[2] ^ S5[GB(z, 0xA)] ^ S6[GB(z, 0x9)] ^ S7[GB(z, 0xb)] ^ S8[GB(z, 0x8)] ^ S6[GB(x, 0xB)];
        skey->cast5.K[i++] = S5[GB(z, 0x8)] ^ S6[GB(z, 0x9)] ^ S7[GB(z, 0x7)] ^ S8[GB(z, 0x6)] ^ S5[GB(z, 0x2)];
        skey->cast5.K[i++] = S5[GB(z, 0xA)] ^ S6[GB(z, 0xB)] ^ S7[GB(z, 0x5)] ^ S8[GB(z, 0x4)] ^ S6[GB(z, 0x6)];
        skey->cast5.K[i++] = S5[GB(z, 0xC)] ^ S6[GB(z, 0xd)] ^ S7[GB(z, 0x3)] ^ S8[GB(z, 0x2)] ^ S7[GB(z, 0x9)];
        skey->cast5.K[i++] = S5[GB(z, 0xE)] ^ S6[GB(z, 0xF)] ^ S7[GB(z, 0x1)] ^ S8[GB(z, 0x0)] ^ S8[GB(z, 0xc)];

        x[3] = z[1] ^ S5[GB(z, 0x5)] ^ S6[GB(z, 0x7)] ^ S7[GB(z, 0x4)] ^ S8[GB(z, 0x6)] ^ S7[GB(z, 0x0)];
        x[2] = z[3] ^ S5[GB(x, 0x0)] ^ S6[GB(x, 0x2)] ^ S7[GB(x, 0x1)] ^ S8[GB(x, 0x3)] ^ S8[GB(z, 0x2)];
        x[1] = z[2] ^ S5[GB(x, 0x7)] ^ S6[GB(x, 0x6)] ^ S7[GB(x, 0x5)] ^ S8[GB(x, 0x4)] ^ S5[GB(z, 0x1)];
        x[0] = z[0] ^ S5[GB(x, 0xA)] ^ S6[GB(x, 0x9)] ^ S7[GB(x, 0xb)] ^ S8[GB(x, 0x8)] ^ S6[GB(z, 0x3)];
        skey->cast5.K[i++] = S5[GB(x, 0x3)] ^ S6[GB(x, 0x2)] ^ S7[GB(x, 0xc)] ^ S8[GB(x, 0xd)] ^ S5[GB(x, 0x8)];
        skey->cast5.K[i++] = S5[GB(x, 0x1)] ^ S6[GB(x, 0x0)] ^ S7[GB(x, 0xe)] ^ S8[GB(x, 0xf)] ^ S6[GB(x, 0xd)];
        skey->cast5.K[i++] = S5[GB(x, 0x7)] ^ S6[GB(x, 0x6)] ^ S7[GB(x, 0x8)] ^ S8[GB(x, 0x9)] ^ S7[GB(x, 0x3)];
        skey->cast5.K[i++] = S5[GB(x, 0x5)] ^ S6[GB(x, 0x4)] ^ S7[GB(x, 0xa)] ^ S8[GB(x, 0xb)] ^ S8[GB(x, 0x7)];

        /* second half */
        z[3] = x[3] ^ S5[GB(x, 0xD)] ^ S6[GB(x, 0xF)] ^ S7[GB(x, 0xC)] ^ S8[GB(x, 0xE)] ^ S7[GB(x, 0x8)];
        z[2] = x[1] ^ S5[GB(z, 0x0)] ^ S6[GB(z, 0x2)] ^ S7[GB(z, 0x1)] ^ S8[GB(z, 0x3)] ^ S8[GB(x, 0xA)];
        z[1] = x[0] ^ S5[GB(z, 0x7)] ^ S6[GB(z, 0x6)] ^ S7[GB(z, 0x5)] ^ S8[GB(z, 0x4)] ^ S5[GB(x, 0x9)];
        z[0] = x[2] ^ S5[GB(z, 0xA)] ^ S6[GB(z, 0x9)] ^ S7[GB(z, 0xb)] ^ S8[GB(z, 0x8)] ^ S6[GB(x, 0xB)];
        skey->cast5.K[i++] = S5[GB(z, 0x3)] ^ S6[GB(z, 0x2)] ^ S7[GB(z, 0xc)] ^ S8[GB(z, 0xd)] ^ S5[GB(z, 0x9)];
        skey->cast5.K[i++] = S5[GB(z, 0x1)] ^ S6[GB(z, 0x0)] ^ S7[GB(z, 0xe)] ^ S8[GB(z, 0xf)] ^ S6[GB(z, 0xc)];
        skey->cast5.K[i++] = S5[GB(z, 0x7)] ^ S6[GB(z, 0x6)] ^ S7[GB(z, 0x8)] ^ S8[GB(z, 0x9)] ^ S7[GB(z, 0x2)];
        skey->cast5.K[i++] = S5[GB(z, 0x5)] ^ S6[GB(z, 0x4)] ^ S7[GB(z, 0xa)] ^ S8[GB(z, 0xb)] ^ S8[GB(z, 0x6)];

        x[3] = z[1] ^ S5[GB(z, 0x5)] ^ S6[GB(z, 0x7)] ^ S7[GB(z, 0x4)] ^ S8[GB(z, 0x6)] ^ S7[GB(z, 0x0)];
        x[2] = z[3] ^ S5[GB(x, 0x0)] ^ S6[GB(x, 0x2)] ^ S7[GB(x, 0x1)] ^ S8[GB(x, 0x3)] ^ S8[GB(z, 0x2)];
        x[1] = z[2] ^ S5[GB(x, 0x7)] ^ S6[GB(x, 0x6)] ^ S7[GB(x, 0x5)] ^ S8[GB(x, 0x4)] ^ S5[GB(z, 0x1)];
        x[0] = z[0] ^ S5[GB(x, 0xA)] ^ S6[GB(x, 0x9)] ^ S7[GB(x, 0xb)] ^ S8[GB(x, 0x8)] ^ S6[GB(z, 0x3)];
        skey->cast5.K[i++] = S5[GB(x, 0x8)] ^ S6[GB(x, 0x9)] ^ S7[GB(x, 0x7)] ^ S8[GB(x, 0x6)] ^ S5[GB(x, 0x3)];
        skey->cast5.K[i++] = S5[GB(x, 0xa)] ^ S6[GB(x, 0xb)] ^ S7[GB(x, 0x5)] ^ S8[GB(x, 0x4)] ^ S6[GB(x, 0x7)];
        skey->cast5.K[i++] = S5[GB(x, 0xc)] ^ S6[GB(x, 0xd)] ^ S7[GB(x, 0x3)] ^ S8[GB(x, 0x2)] ^ S7[GB(x, 0x8)];
        skey->cast5.K[i++] = S5[GB(x, 0xe)] ^ S6[GB(x, 0xf)] ^ S7[GB(x, 0x1)] ^ S8[GB(x, 0x0)] ^ S8[GB(x, 0xd)];
   }

   skey->cast5.keylen = keylen;

   return CRYPT_OK;
}

 #define INLINE


INLINE static ulong32 FI(ulong32 R, ulong32 Km, ulong32 Kr)
{
   ulong32 I;
   I = (Km + R);
   I = ROL(I, Kr);
   return ((S1[byte(I, 3)] ^ S2[byte(I,2)]) - S3[byte(I,1)]) + S4[byte(I,0)];
}

INLINE static ulong32 FII(ulong32 R, ulong32 Km, ulong32 Kr)
{
   ulong32 I;
   I = (Km ^ R);
   I = ROL(I, Kr);
   return ((S1[byte(I, 3)] - S2[byte(I,2)]) + S3[byte(I,1)]) ^ S4[byte(I,0)];
}

INLINE static ulong32 FIII(ulong32 R, ulong32 Km, ulong32 Kr)
{
   ulong32 I;
   I = (Km - R);
   I = ROL(I, Kr);
   return ((S1[byte(I, 3)] + S2[byte(I,2)]) ^ S3[byte(I,1)]) - S4[byte(I,0)];
}


int cast5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey) {
   ulong32 R, L;

   LTC_ARGCHK(pt   != NULL);
   LTC_ARGCHK(ct   != NULL);
   LTC_ARGCHK(skey != NULL);

   LOAD32H(L,&pt[0]);
   LOAD32H(R,&pt[4]);
   L ^= FI(R, skey->cast5.K[0], skey->cast5.K[16]);
   R ^= FII(L, skey->cast5.K[1], skey->cast5.K[17]);
   L ^= FIII(R, skey->cast5.K[2], skey->cast5.K[18]);
   R ^= FI(L, skey->cast5.K[3], skey->cast5.K[19]);
   L ^= FII(R, skey->cast5.K[4], skey->cast5.K[20]);
   R ^= FIII(L, skey->cast5.K[5], skey->cast5.K[21]);
   L ^= FI(R, skey->cast5.K[6], skey->cast5.K[22]);
   R ^= FII(L, skey->cast5.K[7], skey->cast5.K[23]);
   L ^= FIII(R, skey->cast5.K[8], skey->cast5.K[24]);
   R ^= FI(L, skey->cast5.K[9], skey->cast5.K[25]);
   L ^= FII(R, skey->cast5.K[10], skey->cast5.K[26]);
   R ^= FIII(L, skey->cast5.K[11], skey->cast5.K[27]);
   if (skey->cast5.keylen > 10) {
      L ^= FI(R, skey->cast5.K[12], skey->cast5.K[28]);
      R ^= FII(L, skey->cast5.K[13], skey->cast5.K[29]);
      L ^= FIII(R, skey->cast5.K[14], skey->cast5.K[30]);
      R ^= FI(L, skey->cast5.K[15], skey->cast5.K[31]);
   }
   STORE32H(R,&ct[0]);
   STORE32H(L,&ct[4]);
   return CRYPT_OK;
}

int cast5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey){
   ulong32 R, L;

   LTC_ARGCHK(pt   != NULL);
   LTC_ARGCHK(ct   != NULL);
   LTC_ARGCHK(skey != NULL);

   LOAD32H(R,&ct[0]);
   LOAD32H(L,&ct[4]);
   if (skey->cast5.keylen > 10) {
      R ^= FI(L, skey->cast5.K[15], skey->cast5.K[31]);
      L ^= FIII(R, skey->cast5.K[14], skey->cast5.K[30]);
      R ^= FII(L, skey->cast5.K[13], skey->cast5.K[29]);
      L ^= FI(R, skey->cast5.K[12], skey->cast5.K[28]);
   }
   R ^= FIII(L, skey->cast5.K[11], skey->cast5.K[27]);
   L ^= FII(R, skey->cast5.K[10], skey->cast5.K[26]);
   R ^= FI(L, skey->cast5.K[9], skey->cast5.K[25]);
   L ^= FIII(R, skey->cast5.K[8], skey->cast5.K[24]);
   R ^= FII(L, skey->cast5.K[7], skey->cast5.K[23]);
   L ^= FI(R, skey->cast5.K[6], skey->cast5.K[22]);
   R ^= FIII(L, skey->cast5.K[5], skey->cast5.K[21]);
   L ^= FII(R, skey->cast5.K[4], skey->cast5.K[20]);
   R ^= FI(L, skey->cast5.K[3], skey->cast5.K[19]);
   L ^= FIII(R, skey->cast5.K[2], skey->cast5.K[18]);
   R ^= FII(L, skey->cast5.K[1], skey->cast5.K[17]);
   L ^= FI(R, skey->cast5.K[0], skey->cast5.K[16]);
   STORE32H(L,&pt[0]);
   STORE32H(R,&pt[4]);

   return CRYPT_OK;
}


int cast5_test(void) {
   static const struct {
       int keylen;
       unsigned char key[16];
       unsigned char pt[8];
       unsigned char ct[8];
   } tests[] = {
     { 16,
       {0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A},
       {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
       {0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2}
     },
     { 10,
       {0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
       {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
       {0xEB, 0x6A, 0x71, 0x1A, 0x2C, 0x02, 0x27, 0x1B},
     },
     { 5,
       {0x01, 0x23, 0x45, 0x67, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
       {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
       {0x7A, 0xC8, 0x16, 0xD1, 0x6E, 0x9B, 0x30, 0x2E}
     }
   };
   int i, y, err;
   symmetric_key key;
   unsigned char tmp[2][8];

   for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
       if ((err = cast5_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) {
          return err;
       }
       cast5_ecb_encrypt(tests[i].pt, tmp[0], &key);
       cast5_ecb_decrypt(tmp[0], tmp[1], &key);
       if ((compare_testvector(tmp[0], 8, tests[i].ct, 8, "CAST5 Encrypt", i) != 0) ||
             (compare_testvector(tmp[1], 8, tests[i].pt, 8, "CAST5 Decrypt", i) != 0)) {
          return CRYPT_FAIL_TESTVECTOR;
       }
      /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
      for (y = 0; y < 8; y++) tmp[0][y] = 0;
      for (y = 0; y < 1000; y++) cast5_ecb_encrypt(tmp[0], tmp[0], &key);
      for (y = 0; y < 1000; y++) cast5_ecb_decrypt(tmp[0], tmp[0], &key);
      for (y = 0; y < 8; y++) if (tmp[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;

   }
   return CRYPT_OK;
}


void cast5_done(symmetric_key *skey)
{
    (void)(skey);
}


int main() {

    int block_size = 8;
    unsigned char ct[block_size];
    unsigned char pt[block_size]= {0x28, 0x85, 0x84, 0x2e, 0xa3, 0xe6, 0x99, 0x9b};//v0[i] = 0x2885842e;v1[i] = 0xa3e6999b;
    symmetric_key skey;
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    int err;

    if((err = cast5_setup(key, 16, 0, &skey)) == CRYPT_OK)
        printf("key sucess\n");
    else
        printf("Setup Error '%s'\n",error_to_string(err));
    printf("cast5\ninput\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n");

    cast5_ecb_encrypt(pt,ct,&skey);

    printf("Crypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",ct[i]);
    }
    printf("\n");

    cast5_ecb_decrypt(ct, pt,&skey);

    printf("Decrypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n\n\n");
    cast5_done(&skey);


    std::cout << "Hello, World!" << std::endl;
    return 0;
}