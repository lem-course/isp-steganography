package isp.steganography;

import javax.crypto.Cipher;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;

/**
 * Assignments:
 * <p>
 * - E1. Modify implementation so that the receiver can read the size of the hidden message
 * from the first 32 bits of the steganogram. After parsing those 32 bits, process
 * the rest of steganogram accordingly.
 * - E2. Add security: Provide secrecy and integrity for the hidden message.
 * - E3. Use the remaining two color channels to enhance the capacity of the steganogram.
 */
public class ImageSteganography {

    /**
     * Encodes given payload into the image and writes the image to file.
     *
     * @param payload The payload to be encoded
     * @param inFile  The filename of the cover image
     * @param outFile The filename of the steganogram
     * @throws IOException
     */
    public static void encode(final byte[] payload, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        final ByteBuffer buff = ByteBuffer.allocate(payload.length + 4);
        buff.putInt(payload.length).put(payload);

        // Convert byte array to bit sequence (array of booleans)
        final boolean[] bits = getBits(buff.array());

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        ImageIO.write(image, "png", new File(outFile));
    }

    public static void encryptEncode(final byte[] payload, final String inFile, final String outFile, final Key key) throws Exception {
        // load the image
        final BufferedImage image = loadImage(inFile);

        final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key);

        final int finalPayloadSize = payload.length + 16 + 12;
        aes.updateAAD(ByteBuffer.allocate(4).putInt(finalPayloadSize));
        final byte[] ct = aes.doFinal(payload);
        final byte[] iv = aes.getIV();

        final byte[] actualPayload = ByteBuffer.allocate(4 + iv.length + ct.length)
                .putInt(finalPayloadSize)
                .put(iv)
                .put(ct)
                .array();

        // Convert byte array to bit sequence (array of booleans)
        final boolean[] bits = getBits(actualPayload);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        ImageIO.write(image, "png", new File(outFile));
    }

    /**
     * Decodes the message from given filename
     *
     * @param fileName The name of the file
     * @return The byte array of the decoded message
     * @throws IOException
     */
    public static byte[] decode(final String fileName) throws IOException {
        final BufferedImage image = loadImage(fileName);

        final boolean[] bits = decode(image);

        return Arrays.copyOfRange(getBytes(bits), 4, bits.length / 8);
    }

    public static byte[] decryptAndDecode(final String fileName, final Key key) throws Exception {
        final BufferedImage image = loadImage(fileName);

        boolean[] bits = decode(image);

        bits = Arrays.copyOfRange(bits, 32, bits.length);

        final byte[] result = getBytes(bits);

        return result;
    }

    /**
     * Loads an image from given filename and returns an instance of the BufferedImage
     * <p>
     * The file has to be located in src/main/resources directory.
     *
     * @param inFile
     * @return
     * @throws IOException If file does not exist
     */
    protected static BufferedImage loadImage(final String inFile) throws IOException {
        return ImageIO.read(new File(inFile));
    }

    /**
     * Encodes given array of bits into given image. The algorithm modifies the
     * least significant bit in the red component of each image pixel.
     *
     * @param payload The array of bits
     * @param image   The image onto which the payload is to be encoded
     */
    protected static void encode(final boolean[] payload, final BufferedImage image) {
        for (int i = image.getMinX(), bitCounter = 0; i < image.getWidth() && bitCounter < payload.length; i++) {
            for (int j = image.getMinY(); j < image.getHeight() && bitCounter < payload.length; j++) {
                final Color original = new Color(image.getRGB(i, j));

                // Let's modify the red component only
                final int newRed = payload[bitCounter] ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                // Create a new color object
                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with the new color
                image.setRGB(i, j, modified.getRGB());

                // Uncomment to see changes in the RGB components
                // System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);

                bitCounter++;
            }
        }
    }

    protected static boolean[] decode(final BufferedImage image) {
        int size = 32; // at first, ready only 4 bytes denoting the payload size
        boolean[] bits = new boolean[size];

        for (int i = image.getMinX(), bitCounter = 0; i < image.getWidth() && bitCounter < bits.length; i++) {
            for (int j = image.getMinY(); j < image.getHeight() && bitCounter < bits.length; j++) {
                final Color color = new Color(image.getRGB(i, j));
                final int red = color.getRed();

                final int lsb = red & 0x1;
                bits[bitCounter] = !(lsb == 0);
                bitCounter++;

                if (bitCounter == 32) {
                    // we've read the payload size
                    final int newSize = ByteBuffer.wrap(getBytes(bits)).getInt();

                    // increase the size of the bits array
                    size += newSize * 8;
                    boolean[] newBits = new boolean[size];
                    System.arraycopy(bits, 0, newBits, 0, bits.length);
                    bits = newBits;
                }
            }
        }

        return bits;
    }

    /**
     * Converts an array of bytes it into an array of bits (booleans)
     *
     * @param bytes array of bytes
     * @return array of bits
     */
    protected static boolean[] getBits(final byte[] bytes) {
        final boolean[] bits = new boolean[bytes.length * 8];

        for (int i = 0, bitCounter = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[bitCounter] = (bytes[i] & (0x01 << j)) != 0;
                bitCounter++;
            }
        }

        return bits;
    }

    /**
     * Converts an array of bits (booleans) into an array of bytes
     *
     * @param bits array of bits
     * @return array of bytes
     */
    protected static byte[] getBytes(boolean[] bits) {
        final byte[] bytes = new byte[bits.length / 8];

        for (int byteIndex = 0; byteIndex < bytes.length; byteIndex++) {
            byte byte_ = 0;

            for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
                byte_ |= (bits[8 * byteIndex + bitIndex] ?
                        (byte) 0x01 :
                        (byte) 0x00) << bitIndex;
            }

            bytes[byteIndex] = byte_;
        }

        return bytes;
    }
}
