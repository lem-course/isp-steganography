package isp.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Agent alice = new Agent("alice", alice2bob, bob2alice, null, "RSA/ECB/OAEPPadding") {
            @Override
            public void execute() throws Exception {
                /*
                - Create an AES cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
            }
        };

        final Agent bob = new Agent("bob", bob2alice, alice2bob, null, "RSA/ECB/OAEPPadding") {
            @Override
            public void execute() throws Exception {
                /*
                - Take the incoming message from the queue;
                - Create an AES cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
            }
        };

        alice.start();
        bob.start();
    }
}
