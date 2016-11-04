package isp.steganography;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.xml.bind.DatatypeConverter;

/**
 * An example of using the authenticated encryption cipher.
 * <p>
 * During the encryption, the Galois-Counter mode automatically
 * creates a MAC and then, during the decryption, it verifies it.
 * <p>
 * What happens, if the cipher text gets modified?
 * What happens, if the IV gets modified?
 * What happens, if the key is incorrect?
 */
public class GCMExample {

    static String hex(byte[] data) {
        return DatatypeConverter.printHexBinary(data);
    }

    public static void main(String[] args) throws Exception {
        // shared key
        SecretKey sharedKey = KeyGenerator.getInstance("AES").generateKey();

        // the payload
        final String message = "this is my message";
        final byte[] pt = message.getBytes("UTF-8");
        System.out.printf("MSG: %s%n", message);
        System.out.printf("PT:  %s%n", hex(pt));

        // encrypt
        final Cipher encryptor = Cipher.getInstance("AES/GCM/NoPadding");
        encryptor.init(Cipher.ENCRYPT_MODE, sharedKey);
        final byte[] ct = encryptor.doFinal(pt);
        System.out.printf("CT:  %s%n", hex(ct));

        // send IV
        final byte[] iv = encryptor.getIV();
        System.out.printf("IV:  %s%n", hex(iv));

        // decrypt
        final Cipher decryptor = Cipher.getInstance("AES/GCM/NoPadding");
        // the length of the IV is 16 bytes (128 bits)
        decryptor.init(Cipher.DECRYPT_MODE, sharedKey, new GCMParameterSpec(128, iv));
        final byte[] pt2 = decryptor.doFinal(ct);
        System.out.printf("PT:  %s%n", hex(pt2));
        System.out.printf("MSG: %s%n", new String(pt2, "UTF-8"));
    }
}
