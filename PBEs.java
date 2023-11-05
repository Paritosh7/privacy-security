import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Example of using Password-based encryption
 */

public class PBEs {
  public static void main(String[] args) throws Exception {

    PBEKeySpec pbeKeySpec;
    PBEParameterSpec pbeParamSpec;
    SecretKeyFactory keyFac;

    // Salt
    byte[] salt = { (byte) 0xc7, (byte) 0x73, (byte) 0x21,
        (byte) 0x8c, (byte) 0x7e, (byte) 0xc8, (byte) 0xee, (byte) 0x99 };
    // Iteration count

    // int count = 100000
    // encryption = 18630080ns

    // int count = 200000
    // encryption = 26364040ns

    // int count = 300000
    // encryption = 38770120ns

    // int count = 400000
    // encryption = 5728760ns

    // int count = 500000
    // encryption = 60370620ns

    // int count = 600000
    // encryption = 75482180ns

    // int count = 700000
    // encryption = 93989860ns

    // int count = 800000
    // encryption = 102902140ns

    // int count = 900000
    // encryption = 112577040ns

    // int count = 1000000
    // encryption = 114427960ns

    // int count = 1100000
    // encryption = 123475180ns

    int count = 1200000;

    // Create PBE parameter set
    pbeParamSpec = new PBEParameterSpec(salt, count);

    // Initialization of the password
    char[] password = "P@$$W0rD".toCharArray();

    // Create parameter for key generation
    pbeKeySpec = new PBEKeySpec(password);

    // Create instance of SecretKeyFactory for password-based encryption
    // using DES and MD5S
    keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

    // Generate a key
    Key pbeKey = keyFac.generateSecret(pbeKeySpec);

    // Encrypt the password

    try {
      System.out.println(" -------- Encryption --------- ");
      byte[] cipherText = encrypt(pbeKey, pbeParamSpec);
      Utils.toHex(cipherText);
      System.out.println(" -------- Decryption --------- ");
      decrypt(cipherText, pbeKey, pbeParamSpec);

      // Printing the CipherText -----
      Utils.toHex(cipherText);
    } catch (Exception e) {
      System.out.println("Exception while encypting the passoword!");
    }
    // System.out.println("cipher : " + Utils.toHex(ciphertext));

  }

  public static byte[] encrypt(Key pbeKey, PBEParameterSpec pbeParamSpec) throws Exception {

    int i = 0;
    long sumOfEncryptionElapsedTime = 0;
    byte[] ciphertext = new byte[0];

    // Create PBE Cipher
    for (i = 0; i < 6; i++) {

      long startEncryptingTime = System.nanoTime();
      Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

      // Initialize PBE Cipher with key and parameters
      pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

      // Our plaintext
      byte[] cleartext = "This is another example".getBytes();

      // Encrypt the plaintext

      ciphertext = pbeCipher.doFinal(cleartext);
      long endEncryptingTime = System.nanoTime();

      long elapsedTime = endEncryptingTime - startEncryptingTime;
      System.out.println("Elapsed time : " + elapsedTime);

      // Excluding the first time as it is giving extremely high value
      if (i != 0) {
        sumOfEncryptionElapsedTime += elapsedTime;
      }
    }
    System.out.println("It took " + (sumOfEncryptionElapsedTime / 5) + "ns to complete the encryption");

    return ciphertext;

  }

  public static void decrypt(byte[] cipherText, Key pbeKey, PBEParameterSpec pbeParamSpec) throws Exception {

    int i = 0;
    long sumOfDecryptionElapsedTime = 0;
    byte[] ciphertext = new byte[0];

    for (i = 0; i < 6; i++) {

      long startDecryptionTime = System.nanoTime();
      Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
      // Initialize PBE Cipher with key and parameters
      pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
      // decrypt the ciphertext
      byte[] plaintext = pbeCipher.doFinal(cipherText);
      long endDecryptionTime = System.nanoTime();

      String stringPlaintext = new String(plaintext);

      long elapsedTime = endDecryptionTime - startDecryptionTime;

      System.out.println((stringPlaintext));

      if (i != 0) {
        sumOfDecryptionElapsedTime += elapsedTime;
      }
    }
    System.out.println("It took " + sumOfDecryptionElapsedTime / 5 + "ns to complete the decryption");
  }
}
