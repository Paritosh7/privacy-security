
import java.security.MessageDigest;

/**
 * 
 */
public class MessageDigestExample {
    public static void main(
            String[] args)
            throws Exception {
        String input = "This is a message!";
        MessageDigest hash = MessageDigest.getInstance("SHA256");

        System.out.println("input : " + input);

        hash.update(Utils.toByteArray(input));

        System.out.println("digest (hash) : " + Utils.toHex(hash.digest()));

    }
}