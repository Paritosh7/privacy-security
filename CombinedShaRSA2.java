import java.security.*;
import javax.crypto.Cipher;

public class CombinedShaRSA2 {

    public static void main(String[] args) throws Exception {
        // Sender
        String originalMessage = "This is a random message";

        // Sender: Calculate SHA-1 hash
        byte[] hashedMessage = calculateSHA1(originalMessage);

        // Sender: Generate RSA key pair
        KeyPair senderKeyPair = generateRSAKeyPair();
        PrivateKey senderPrivateKey = senderKeyPair.getPrivate();
        PublicKey senderPublicKey = senderKeyPair.getPublic();

        // Sender: Encrypt the hash with RSA private key
        byte[] encryptedDigest = encryptWithRSA(hashedMessage, senderPrivateKey);

        // Verifier
        // Verifier: Decrypt the digest with Sender's public key
        byte[] decryptedDigest = decryptWithRSA(encryptedDigest, senderPublicKey);

        // Verifier: Recalculate SHA-1 hash from the received message
        byte[] recalculatedHash = calculateSHA1(originalMessage);

        // Verifier: Compare and print the digests
        System.out.println("Original Hash: " + bytesToHex(hashedMessage));
        System.out.println("Decrypted Hash: " + bytesToHex(decryptedDigest));

        // Verify if the message has been changed
        if (MessageDigest.isEqual(recalculatedHash, decryptedDigest)) {
            System.out.println("Message is unchanged.");
        } else {
            System.out.println("Warning: The message has been changed!");
        }

        // Modify the encrypted digest (simulate an attack)
        // encryptedDigest[0] = (byte) (encryptedDigest[0] ^ 1);

        // Verify if the encrypted digest has been changed
        if (MessageDigest.isEqual(hashedMessage, decryptWithRSA(encryptedDigest, senderPublicKey))) {
            System.out.println("Encrypted Digest is unchanged.");
        } else {
            System.out.println("Warning: The encrypted digest has been changed!");
        }

        // Modify both the message and encrypted digest (simulate an attack)
        // originalMessage += " (modified)";
        // encryptedDigest[0] = (byte) (encryptedDigest[0] ^ 1);

        // Verify if both the message and encrypted digest have been changed
        if (MessageDigest.isEqual(recalculatedHash, decryptedDigest) &&
                MessageDigest.isEqual(hashedMessage, decryptWithRSA(encryptedDigest, senderPublicKey))) {
            System.out.println("Message and Encrypted Digest are unchanged.");
        } else {
            System.out.println("Warning: Both message and encrypted digest have been changed!");
        }
    }

    private static byte[] calculateSHA1(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(message.getBytes());
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You may adjust the key size as needed
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptWithRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptWithRSA(byte[] encryptedData, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedData);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte b : bytes) {
            hexStringBuilder.append(String.format("%02x", b));
        }
        return hexStringBuilder.toString();
    }
}
