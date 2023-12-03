import java.security.MessageDigest;

public class MessageHashing256 {

    public static void main(
            String[] args)
            throws Exception {

        String input = "Random Message";
        MessageDigest hash = MessageDigest.getInstance("SHA256");

        // Input Message
        System.out.println("input : " + input);

        // Hashing the message
        hash.update(Utils.toByteArray(input));

        // Hashed value
        System.out.println("digest (hash) : " + Utils.toHex(hash.digest()));

    }

}
