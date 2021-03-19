#include <AESLib.h>
#include <hydrogen.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)( \
  b ^= ROTL(a + d, 7), \
  c ^= ROTL(b + a, 9), \
  d ^= ROTL(c + b, 13), \
  a ^= ROTL(d + c, 18))
#define ROUNDS 20
#define MESSAGE_LEN 4
#define CONTEXT "Example"

void chacha20_block(uint32_t out[16], uint32_t const in[16]) {
  int i;
  uint32_t x[16];
  for (i=0; i<16; ++i) x[i] = in[i];
  //10 loops x 2 rounds/loop = 20 rounds
  for (i=0; i<ROUNDS; i+=2){
    //Odd Round
    QR(x[0], x[4], x[8], x[12]);
    QR(x[1], x[5], x[9], x[13]);
    QR(x[2], x[6], x[10], x[14]);
    QR(x[3], x[7], x[11], x[15]);
    //Even Rounds
    QR(x[0], x[5], x[10], x[15]);
    QR(x[1], x[6], x[11], x[12]);
    QR(x[2], x[7], x[8], x[13]);
    QR(x[3], x[4], x[9], x[14]);
  }
  for (i=0; i<16; ++i) out[i] = x[i] + in[i];
}

void setup() {
  // put your setup code here, to run once:

  uint32_t C[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
  uint32_t K[8] = {0xa25171d3, 0x8a02f891, 0xc7285be1, 0x9243bf52, 0x9c5f064f, 0xd8bcddf4, 0x3dd45797, 0x4141699c};
  uint32_t cont[2] = {0x1, 0x1};
  uint32_t nonce[2] = {0x081edde9, 0x2b053cfd};
  uint32_t in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0xa25171d3, 0x8a02f891, 0xc7285be1, 0x9243bf52, 0x9c5f064f, 0xd8bcddf4, 0x3dd45797, 0x4141699c, 0x1, 0x1, 0x081edde9, 0x2b053cfd};
  uint32_t out[16];
  uint8_t* xorarray = (uint8_t *)malloc(16 * sizeof(uint8_t));
  
  Serial.begin(57600);
  uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  char data[] = "Crypto Final!!!"; //16 chars == 16 bytes
  aes128_enc_single(key, data);
  Serial.print("Encrypted with AES128:");
  Serial.println(data);

  //uint32_t in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0xa25171d3, 0x8a02f891, 0xc7285be1, 0x9243bf52, 0x9c5f064f, 0xd8bcddf4, 0x3dd45797, 0x4141699c, 0x1, 0x1, 0x081edde9, 0x2b053cfd};
  //char data[] = "Goya Goya, Kachun Kachun Ra Ra, Kachun Kachun Ra Ra, Goya, Universidad";
  //uint8_t temp[50];
  int i;
  uint8_t encrypt[50];
  uint8_t decrypt[70];
  Serial.print("Encrypted string with Chacha20: ");
  for(i=0; i<sizeof(data); i++){
    chacha20_block(out, in);
    xorarray = (uint8_t*)in;
    encrypt[i] = data[i] ^ xorarray[i];
    Serial.print(encrypt[i]);
  }
  Serial.print("\n");
  
  hydro_sign_keypair key_pair;
  hydro_sign_keygen(&key_pair);

  uint8_t signature[hydro_sign_BYTES];

  /* Sign the message using the secret key */
  hydro_sign_create(signature, data, MESSAGE_LEN, CONTEXT, key_pair.sk);
  Serial.print("RSA Signature: ");
  for(int i=0; i<hydro_sign_BYTES; i++){
    Serial.print(signature[i]);
  }
  Serial.println("");
  
  /* Verify the signature using the public key */
  if (hydro_sign_verify(signature, data, MESSAGE_LEN, CONTEXT, key_pair.pk) != 0) {
      /* forged */
    Serial.print("Signature not verified. Forged!");
  } else {
    Serial.print("Signature verified!");
  }

  Serial.println("");
  Serial.print("Decrypted string with Chacha20: ");
  for(i=0; i<sizeof(data) - 1; i++){
    chacha20_block(out, in);
    xorarray = (uint8_t*)in;
    decrypt[i] = encrypt[i] ^ xorarray[i];
    Serial.print(decrypt[i] - 48);
    Serial.print(" ");
  }
  Serial.print("\n");

  aes128_dec_single(key, data);
  Serial.print("Decrypted with AES128:");
  Serial.println(data);

  
  return 0;

  
  
}

void loop() {
  // put your main code here, to run repeatedly:

}
