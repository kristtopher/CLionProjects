#include <iostream>
#include <tomcrypt.h>

int main() {
    int block_size = 8;
    unsigned char ct[block_size];
    unsigned char pt[block_size]= {0x28, 0x85, 0x84, 0x2e, 0xa3, 0xe6, 0x99, 0x9b};//v0[i] = 0x2885842e;v1[i] = 0xa3e6999b;
    symmetric_key skey;
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0xCA,0x7D};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};
    int err;

     if((err = xtea_setup(key, 16, 0, &skey)) == CRYPT_OK)
         printf("key sucess\n");
     else
         printf("Setup Error '%s'\n",error_to_string(err));

     printf("XTEA\ninput\n");
     for (int i = 0; i < block_size; ++i) {
         printf("%x ",pt[i]);
     }
     printf("\n");

     xtea_ecb_encrypt(pt,ct,&skey);

     printf("Crypt\n");
     for (int i = 0; i < block_size; ++i) {
         printf("%x ",ct[i]);
     }
     printf("\n");

     xtea_ecb_decrypt(ct, pt,&skey);

     printf("Decrypt\n");
     for (int i = 0; i < block_size; ++i) {
         printf("%x ",pt[i]);
     }
     printf("\n\n\n");
     xtea_done(&skey);



//    if((err = blowfish_setup(Bkey, 8, 0, &skey)) == CRYPT_OK)
//        printf("key sucess\n");
//    else
//        printf("Setup Error '%s'\n",error_to_string(err));
//
//    printf("Blowfish\ninput\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n");
//
//    blowfish_ecb_encrypt(pt,ct,&skey);
//
//    printf("Crypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",ct[i]);
//    }
//    printf("\n");
//
//    blowfish_ecb_decrypt(ct, pt,&skey);
//
//    printf("Decrypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n\n\n");
//    blowfish_done(&skey);



//   if((err = rc5_setup(key, 16, 0, &skey)) == CRYPT_OK)
//       printf("key sucess\n");
//   else
//       printf("Setup Error '%s'\n",error_to_string(err));
//   printf("RC5\ninput\n");
//   for (int i = 0; i < block_size; ++i) {
//       printf("%x ",pt[i]);
//   }
//   printf("\n");
//
//   rc5_ecb_encrypt(pt,ct,&skey);
//
//   printf("Crypt\n");
//   for (int i = 0; i < block_size; ++i) {
//       printf("%x ",ct[i]);
//   }
//   printf("\n");
//
//   rc5_ecb_decrypt(ct, pt,&skey);
//
//   printf("Decrypt\n");
//   for (int i = 0; i < block_size; ++i) {
//       printf("%x ",pt[i]);
//   }
//   printf("\n\n\n");
//   rc5_done(&skey);


//      if((err = rc2_setup(key, 16, 0, &skey)) == CRYPT_OK)
//          printf("key sucess\n");
//      else
//          printf("Setup Error '%s'\n",error_to_string(err));
//      printf("RC2\ninput\n");
//      for (int i = 0; i < block_size; ++i) {
//          printf("%x ",pt[i]);
//      }
//      printf("\n");
//
//      rc2_ecb_encrypt(pt,ct,&skey);
//
//      printf("Crypt\n");
//      for (int i = 0; i < block_size; ++i) {
//          printf("%x ",ct[i]);
//      }
//      printf("\n");
//
//      rc2_ecb_decrypt(ct, pt,&skey);
//
//      printf("Decrypt\n");
//      for (int i = 0; i < block_size; ++i) {
//          printf("%x ",pt[i]);
//      }
//      printf("\n\n\n");
//      rc2_done(&skey);



//    if((err = kasumi_setup(key, 16, 0, &skey)) == CRYPT_OK)
//        printf("key sucess\n");
//    else
//        printf("Setup Error '%s'\n",error_to_string(err));
//    printf("kasumi\ninput\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n");
//
//    kasumi_ecb_encrypt(pt,ct,&skey);
//
//    printf("Crypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",ct[i]);
//    }
//    printf("\n");
//
//    kasumi_ecb_decrypt(ct, pt,&skey);
//
//    printf("Decrypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n\n\n");
//    kasumi_done(&skey);
//
//    if((err = des_setup(Bkey, 8, 0, &skey)) == CRYPT_OK)
//        printf("key sucess\n");
//    else
//        printf("Setup Error '%s'\n",error_to_string(err));
//    printf("des\ninput\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n");
//
//    des_ecb_encrypt(pt,ct,&skey);
//
//    printf("Crypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",ct[i]);
//    }
//    printf("\n");
//
//    des_ecb_decrypt(ct, pt,&skey);
//
//    printf("Decrypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n\n\n");
//    des_done(&skey);



//   if((err = safer_k64_setup(Bkey, 8, 0, &skey)) == CRYPT_OK)
//       printf("key sucess\n");
//   else
//       printf("Setup Error '%s'\n",error_to_string(err));
//   printf("safer_k64\ninput\n");
//   for (int i = 0; i < block_size; ++i) {
//       printf("%x ",pt[i]);
//   }
//   printf("\n");
//
//   safer_ecb_encrypt(pt,ct,&skey);
//
//   printf("Crypt\n");
//   for (int i = 0; i < block_size; ++i) {
//       printf("%x ",ct[i]);
//   }
//   printf("\n");
//
//   safer_ecb_decrypt(ct, pt,&skey);
//
//   printf("Decrypt\n");
//   for (int i = 0; i < block_size; ++i) {
//       printf("%x ",pt[i]);
//   }
//   printf("\n\n\n");
//   safer_done(&skey);




//    if((err = skipjack_setup(Skey, 10, 0, &skey)) == CRYPT_OK)
//        printf("key sucess\n");
//    else
//        printf("Setup Error '%s'\n",error_to_string(err));
//    printf("skipjack\ninput\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n");
//
//    skipjack_ecb_encrypt(pt,ct,&skey);
//
//    printf("Crypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",ct[i]);
//    }
//    printf("\n");
//
//    skipjack_ecb_decrypt(ct, pt,&skey);
//
//    printf("Decrypt\n");
//    for (int i = 0; i < block_size; ++i) {
//        printf("%x ",pt[i]);
//    }
//    printf("\n\n\n");
//    skipjack_done(&skey);
    return 0;
}