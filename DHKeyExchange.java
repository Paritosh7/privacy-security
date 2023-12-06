import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class DHKeyExchange {

    public static void main(String args[]) throws Exception {

        // party1 creates a DH key pair
        KeyPairGenerator party1KeyPairGenObj = KeyPairGenerator.getInstance("DH");
        party1KeyPairGenObj.initialize(2048);
        KeyPair party1KeyPair = party1KeyPairGenObj.generateKeyPair();

        /**
         * DHParameterSpec that will be shared among all the parties
         * The parameters that we get here are g (base) and p (modulo) which are further
         * used
         */
        DHParameterSpec dhParamterShared = ((DHPublicKey) party1KeyPair.getPublic()).getParams();

        // party2 creates a DH key pair using the shared dh params.
        KeyPairGenerator party2KeyPairGenObj = KeyPairGenerator.getInstance("DH");
        party2KeyPairGenObj.initialize(dhParamterShared);
        KeyPair party2KeyPair = party2KeyPairGenObj.generateKeyPair();

        // The same keypair generation will follow for the other parties.

        // party3 creates a DH key pair using the shared dh params.
        KeyPairGenerator party3KeyPairGenObj = KeyPairGenerator.getInstance("DH");
        party3KeyPairGenObj.initialize(dhParamterShared);
        KeyPair party3KeyPair = party2KeyPairGenObj.generateKeyPair();

        // party4 creates a DH key pair using the shared dh params.
        KeyPairGenerator party4KeyPairGenObj = KeyPairGenerator.getInstance("DH");
        party4KeyPairGenObj.initialize(dhParamterShared);
        KeyPair party4KeyPair = party2KeyPairGenObj.generateKeyPair();

        /**
         * Now each party will create a public key.
         * This will be achieved using their respective private keys and the values g, p
         * Formula used: g ^ privatekey mod p
         */

        // Party1
        KeyAgreement party1KeyAgreementObj = KeyAgreement.getInstance("DH");
        party1KeyAgreementObj.init(party1KeyPair.getPrivate());

        // Party2
        KeyAgreement party2KeyAgreementObj = KeyAgreement.getInstance("DH");
        party2KeyAgreementObj.init(party2KeyPair.getPrivate());

        // Party3
        KeyAgreement party3KeyAgreementObj = KeyAgreement.getInstance("DH");
        party3KeyAgreementObj.init(party3KeyPair.getPrivate());

        // Party4
        KeyAgreement party4KeyAgreementObj = KeyAgreement.getInstance("DH");
        party4KeyAgreementObj.init(party4KeyPair.getPrivate());

        /**
         * Now each party have to send the result to other party.
         * For 4 parties the maximum passes will be 3
         * Each time the recieved party raises the public key to the power of the
         * privatekey modulo p
         * Building the shared public in each phase
         */

        // Sharing phase 1

        // Party 1 computes keyBuild41
        Key keyBuild41 = party1KeyAgreementObj.doPhase(party4KeyPair.getPublic(), false);

        // Party 2 computes keyBuild12
        Key keyBuild12 = party2KeyAgreementObj.doPhase(party1KeyPair.getPublic(), false);

        // Party 3 computes keyBuild23
        Key keyBuild23 = party3KeyAgreementObj.doPhase(party2KeyPair.getPublic(), false);

        // Party 4 computes keyBuild34
        Key keyBuild34 = party4KeyAgreementObj.doPhase(party3KeyPair.getPublic(), false);

        // Sharing phase 2

        // Party 1 computes keyBuild 341
        Key keyBuild341 = party1KeyAgreementObj.doPhase(keyBuild34, false);

        // Party 2 computes keyBuild 412
        Key keyBuild412 = party2KeyAgreementObj.doPhase(keyBuild41, false);

        // Party 3 computes keyBuild 123
        Key keyBuild123 = party3KeyAgreementObj.doPhase(keyBuild12, false);

        // Party 4 computes keyBuild 234
        Key keyBuild234 = party4KeyAgreementObj.doPhase(keyBuild23, false);

        // This is the last phase and the boolean last phase will be true now.

        // Party1 computes keyBuild 2341
        Key keyBuild2341 = party1KeyAgreementObj.doPhase(keyBuild234, true);

        Key keyBuild3412 = party2KeyAgreementObj.doPhase(keyBuild341, true);

        Key keyBuild4123 = party3KeyAgreementObj.doPhase(keyBuild412, true);

        Key keyBuild1234 = party4KeyAgreementObj.doPhase(keyBuild123, true);

        // All the parties generating secret
        byte[] party1SharedSecret = party1KeyAgreementObj.generateSecret();
        byte[] party2SharedSecret = party2KeyAgreementObj.generateSecret();
        byte[] party3SharedSecret = party3KeyAgreementObj.generateSecret();
        byte[] party4SharedSecret = party4KeyAgreementObj.generateSecret();

        // Comparing the secrets
        compareSecrets(party1SharedSecret, party2SharedSecret, party3SharedSecret, party4SharedSecret);

        /**
         * If the shared secret is same between parties
         * It can be used to encrypt as well decrypt data
         * as all the parties will have to same key.
         */

    }

    private static void compareSecrets(byte[] party1SharedSecret, byte[] party2SharedSecret, byte[] party3SharedSecret,
            byte[] party4SharedSecret) {

        if (java.util.Arrays.equals(party1SharedSecret, party2SharedSecret))
            System.out.println("Party1 and Party2 shared secret is the same");

        else
            System.out.println("Party1 and Party2 shared secret is different");

        if (java.util.Arrays.equals(party2SharedSecret, party3SharedSecret))
            System.out.println("Party2 and Party3 shared secret is the same");

        else
            System.out.println("Party2 and Party3 shared secret is different");

        if (java.util.Arrays.equals(party3SharedSecret, party4SharedSecret))
            System.out.println("Party3 and Party4 shared secret is the same");

        else
            System.out.println("Party3 and Party4 shared secret is different");

    }
}
