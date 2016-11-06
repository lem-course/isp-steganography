package isp.steganography;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.imageio.ImageIO;
import javax.xml.bind.DatatypeConverter;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;
import java.util.BitSet;

/**
 * Assignments:
 * <p>
 * 1. Change the encoding process, so that the first 4 bytes of the steganogram hold the
 * length of the payload. Then modify the decoding process accordingly.
 * 2. Add security: Provide secrecy and integrity for the hidden message. Use GCM for cipher.
 * Also, use AEAD to provide integrity to the steganogram size.
 * 3. Extra: Enhance the capacity of the carrier:
 * -- Use the remaining two color channels;
 * -- Use additional bits.
 */
public class ImageSteganography {

    public static String hex(byte[] data) {
        return DatatypeConverter.printHexBinary(data);
    }

    /**
     * Encodes given payload into the cover image and saves the steganogram.
     *
     * @param pt      The payload to be encoded
     * @param inFile  The filename of the cover image
     * @param outFile The filename of the steganogram
     * @throws IOException If the file does not exist, or the saving fails.
     */
    public static void encode(final byte[] pt, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        // extend the payload with its size
        final byte[] payload = ByteBuffer.allocate(pt.length + 4)
                .putInt(pt.length)
                .put(pt)
                .array();

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(payload);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decodes the message from given filename.
     *
     * @param fileName The name of the file
     * @return The byte array of the decoded message
     * @throws IOException If the filename does not exist.
     */
    public static byte[] decode(final String fileName) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decode(image);

        // convert them to bytes
        final byte[] bytes = bits.toByteArray();

        // return bytes without the first four bytes (that denote the size)
        return Arrays.copyOfRange(bytes, 4, bytes.length);
    }

    /**
     * Encrypts and encodes given plain text into the cover image and then saves the steganogram.
     *
     * @param pt      The plaintext of the payload
     * @param inFile  cover image filename
     * @param outFile steganogram filename
     * @param key     symmetric secret key
     * @throws Exception
     */
    public static void encryptAndEncode(final byte[] pt, final String inFile, final String outFile, final Key key)
            throws Exception {
        final BufferedImage image = loadImage(inFile);

        final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key);

        // len(CT) = len(PT) + len(tag)
        // len(payload) = len(CT) + len(IV)
        final int finalPayloadSize = 12 + pt.length + 16;
        aes.updateAAD(ByteBuffer.allocate(4).putInt(finalPayloadSize));
        final byte[] ct = aes.doFinal(pt);
        final byte[] iv = aes.getIV();

        final byte[] payload = ByteBuffer.allocate(4 + finalPayloadSize)
                .putInt(finalPayloadSize)
                .put(iv)
                .put(ct)
                .array();

        // Convert byte array to bit sequence (array of booleans)
        final BitSet bits = BitSet.valueOf(payload);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decrypts and then decodes the message from the steganogram.
     *
     * @param fileName name of the steganogram
     * @param key      symmetric secret key
     * @return plaintext of the decoded message
     * @throws Exception
     */
    public static byte[] decryptAndDecode(final String fileName, final Key key) throws Exception {
        final BufferedImage image = loadImage(fileName);

        final byte[] bytes = decode(image).toByteArray();

        final ByteBuffer buff = ByteBuffer.wrap(bytes);

        final int size = buff.getInt();

        final byte[] iv = new byte[12];
        buff.get(iv);

        final byte[] ct = new byte[size - 12];
        buff.get(ct);

        final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        aes.updateAAD(ByteBuffer.allocate(4).putInt(size));
        return aes.doFinal(ct);
    }

    /**
     * Loads an image from given filename and returns an instance of the BufferedImage
     *
     * @param inFile filename of the image
     * @return image
     * @throws IOException If file does not exist
     */
    protected static BufferedImage loadImage(final String inFile) throws IOException {
        return ImageIO.read(new File(inFile));
    }

    /**
     * Saves given image into file
     *
     * @param outFile image filename
     * @param image   image to be saved
     * @throws IOException If an error occurs while writing to file
     */
    protected static void saveImage(String outFile, BufferedImage image) throws IOException {
        ImageIO.write(image, "png", new File(outFile));
    }

    /**
     * Encodes given array of bits into given image. The algorithm modifies the
     * least significant bit in the red component of each image pixel.
     *
     * @param payload The array of bits
     * @param image   The image onto which the payload is to be encoded
     */
    protected static void encode(final BitSet payload, final BufferedImage image) {
        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < payload.size(); x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < payload.size(); y++) {
                final Color original = new Color(image.getRGB(x, y));

                // Let's modify the red component only
                final int newRed = payload.get(bitCounter) ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                // Create a new color object
                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with the new color
                image.setRGB(x, y, modified.getRGB());

                // Uncomment to see changes in the RGB components
                // System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);

                bitCounter++;
            }
        }
    }

    /**
     * Decodes the message from the steganogram
     *
     * @param image steganogram
     * @return {@link BitSet} instance representing the sequence of read bits
     */
    protected static BitSet decode(final BufferedImage image) {
        int size = 32; // at first, ready only 32 bits (4 bytes) denoting the payload size
        final BitSet bits = new BitSet(size);

        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < size; x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < size; y++) {
                final Color color = new Color(image.getRGB(x, y));
                final int lsb = color.getRed() & 0x1;
                bits.set(bitCounter, !(lsb == 0));
                bitCounter++;

                if (bitCounter == 32) {
                    // we've read the payload size
                    final int newSize = ByteBuffer.wrap(bits.toByteArray()).getInt();

                    // increase the number of bits to read
                    size += newSize * 8;
                }
            }
        }

        return bits;
    }
}
