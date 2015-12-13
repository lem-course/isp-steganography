package isp.steganography;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * EXERCISE:
 * <p/>
 * - E1. Ensure initial initialOffset when encoding LSB bits
 * - E2. Ensure Implement changing distance between LSB bits
 * - E3. Implement EOF auto-detection
 * - E4. Switch between RGB values
 * - E5. Use encryption (e.g. AES) to provide bits secrecy
 * - E6. Use HMAC to provide bits authenticity and data integrity
 */
public class ImageSteganography {

    protected final BufferedImage image;
    protected final Key key;

    public ImageSteganography(final String inFile, final Key aesKey) {
        try {
            image = loadFile(inFile);
            key = aesKey;
        } catch (IOException e) {
            throw new IllegalArgumentException("An invalid input image: " + e.getMessage());
        }
    }

    public void encodeAndEncrypt(final String outFile, final byte[] payload)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException {

        // payload + 16 bytes for Galois MAC
        final byte[] payloadSize = ByteBuffer.allocate(4).putInt(payload.length + 16).array();

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final byte[] ap = cipher.getParameters().getEncoded();

        System.out.println(Arrays.toString(ap));

        // GCM: Authenticate AP and size
        // todo: cipher.updateAAD(ap);
        // todo: cipher.updateAAD(payloadSize);
        final byte[] cipherText = cipher.doFinal(payload);

        // merge AP and cipherText arrays
        final byte[] finalPayload = Arrays.copyOf(ap, ap.length + cipherText.length);
        System.arraycopy(cipherText, 0, finalPayload, ap.length, cipherText.length);
        System.out.printf("size=4, pt=%d, ap=%d, ct=%d%n", payload.length, ap.length, cipherText.length);

        final boolean[] size = getBits(payloadSize);
        final boolean[] bits = getBits(finalPayload);

        // merge all bits into a single array
        final boolean[] bitPayload = Arrays.copyOf(size, size.length + bits.length);
        System.arraycopy(bits, 0, bitPayload, size.length, bits.length);

        // encode the bits into image
        encode(bitPayload, image);

        // save the modified image into outFile
        ImageIO.write(image, "png", new File(outFile));
    }

    public void encode(final String outFile, final byte[] payload) throws IOException {
        final boolean[] size = getBits(ByteBuffer.allocate(4).putInt(payload.length).array());
        final boolean[] bits = getBits(payload);

        final boolean[] bitPayload = Arrays.copyOf(size, size.length + bits.length);
        System.arraycopy(bits, 0, bitPayload, size.length, bits.length);

        // encode the bits into image
        encode(bitPayload, image);

        // save the modified image into outFile
        ImageIO.write(image, "png", new File(outFile));
    }

    public byte[] decode() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        final boolean[] bits = decode(image);

        final byte[] bytes = getBytes(bits);
        if (key == null) {
            return bytes;
        } else {
            // todo: decrypt
            final AlgorithmParameters ap = AlgorithmParameters.getInstance("AES");
            final byte[] apBytes = Arrays.copyOfRange(bytes, 0, 19);
            System.out.println(Arrays.toString(apBytes));
            ap.init(apBytes); // first 19 bytes are AP

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, ap);

            // cipher.updateAAD(ap.getEncoded());
            // cipher.updateAAD(payloadSize);
            return cipher.doFinal(Arrays.copyOfRange(bytes, 19, bytes.length));
        }
    }

    /**
     * Converts an array of bytes it into an array of bits (booleans)
     *
     * @param bytes
     * @return
     */
    protected boolean[] getBits(final byte[] bytes) {
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
     * Loads a file from given name and returns an instance of the BufferedImage
     * <p/>
     * The file has to be located in src/main/resources directory.
     *
     * @param inFile
     * @return
     * @throws IOException If file does not exist
     */
    protected BufferedImage loadFile(final String inFile) throws IOException {
        return ImageIO.read(new File(inFile));
    }

    /**
     * Encodes given array of bits into given image. The algorithm modifies the
     * least significant bit in the red component of each image pixel.
     *
     * @param payload The array of bits
     * @param image   The image onto which the payload is to be encoded
     */
    protected final void encode(final boolean[] payload, final BufferedImage image) {
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
                //System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);

                bitCounter++;
            }
        }
    }

    protected final boolean[] decode(final BufferedImage image) {
        boolean[] bits = new boolean[32];
        final boolean[] size = new boolean[32];

        for (int i = image.getMinX(), bitCounter = 0;
             i < image.getWidth() && bitCounter < bits.length + size.length; i++) {
            for (int j = image.getMinY(); j < image.getHeight() && bitCounter < bits.length + size.length; j++) {
                final Color color = new Color(image.getRGB(i, j));
                final int red = color.getRed();

                if (bitCounter < 32) {
                    // find out the size
                    size[bitCounter] = ((red & 0x1) != 0);

                    if (bitCounter == 31) {
                        // last iteration
                        final int length = ByteBuffer.wrap(getBytes(size)).getInt();
                        bits = new boolean[length * 8];

                        System.out.printf("Size in bytes: %d%n", length);
                    }
                } else {
                    bits[bitCounter - 32] = ((red & 0x1) != 0);
                }

                bitCounter++;
            }
        }

        return bits;
    }

    protected byte[] getBytes(boolean[] bits) {
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
