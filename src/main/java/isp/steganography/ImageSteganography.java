package isp.steganography;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This solution requires JDK 8.
 */
public class ImageSteganography {

    /**
     * length of IV for GCM
     */
    public static final int IV_LENGTH = 12;

    /**
     * The number of bits representing the size of the encoded payload
     */
    public static final int SIZE_LENGTH_BITS = 32;
    public static final int GMAC_SIZE = 16;
    protected final BufferedImage image;
    protected final Key key;

    public ImageSteganography(final String inFile) {
        this(inFile, null);
    }

    public ImageSteganography(final String inFile, final Key aesKey) {
        try {
            image = loadFile(inFile);
            key = aesKey;
        } catch (IOException e) {
            throw new IllegalArgumentException("An invalid input image: " + e.getMessage());
        }
    }

    public void encode(final String outFile, final byte[] payload) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (key == null) {
            doEncode(outFile, payload);
        } else {
            doEncodeAndEncrypt(outFile, payload);
        }
    }

    protected void doEncodeAndEncrypt(final String outFile, final byte[] payload)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException {
        // Encryption cipher: GCM (This requires JAVA 8)
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        /* The size of the encoded payload is the size of the actual payload plus the
         * 16 bytes (128 bits) for Galois MAC (GMAC). Note that the size of the cipher
         * text is the same as the size of the plaint text, since GCM is in effect a
         * stream cipher.
         */
        final byte[] payloadSize = ByteBuffer.allocate(4).putInt(payload.length + GMAC_SIZE).array();

        // IV
        final byte[] iv = cipher.getIV();

        // GCM: Authenticate IV
        cipher.updateAAD(iv);

        // GCM: Authenticate size
        cipher.updateAAD(payloadSize);

        // encrypt
        final byte[] cipherText = cipher.doFinal(payload);

        // merge IV and cipherText arrays
        final byte[] ivAndPayload = Arrays.copyOf(iv, iv.length + cipherText.length);
        System.arraycopy(cipherText, 0, ivAndPayload, iv.length, cipherText.length);

        // convert bytes to bits
        final boolean[] size = getBits(payloadSize);
        final boolean[] bits = getBits(ivAndPayload);

        // merge both bits arrays
        final boolean[] bitPayload = Arrays.copyOf(size, size.length + bits.length);
        System.arraycopy(bits, 0, bitPayload, size.length, bits.length);

        // encode the bits into image
        encode(bitPayload, image);

        // save the modified image to outFile
        ImageIO.write(image, "png", new File(outFile));
    }

    protected void doEncode(final String outFile, final byte[] payload) throws IOException {
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
        final boolean[][] decoded = decode(image);

        final byte[] size = getBytes(decoded[0]);
        final byte[] payload = getBytes(decoded[1]);

        if (key == null) {
            return payload;
        } else {
            // The first IV_LENGTH bytes are the IV
            final byte[] iv = Arrays.copyOfRange(payload, 0, IV_LENGTH);

            // Set the GCM parameters
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(8 * GMAC_SIZE, iv);

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

            // Authenticate IV
            cipher.updateAAD(iv);

            // Authenticate size
            cipher.updateAAD(size);
            final byte[] encryptedPayload = Arrays.copyOfRange(payload, IV_LENGTH, payload.length);

            return cipher.doFinal(encryptedPayload);
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
     * <p>
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

                int newRed = original.getRed();
                int newGreen = original.getGreen();
                int newBlue = original.getBlue();

                for (byte rgb = 0; rgb < 3 && bitCounter < payload.length; rgb++, bitCounter++) {
                    switch (rgb) {
                        case 0:
                            newRed = payload[bitCounter] ?
                                    newRed | 0x01 : // sets LSB to 1
                                    newRed & 0xfe;  // sets LSB to 0
                            break;
                        case 1:
                            newGreen = payload[bitCounter] ?
                                    newGreen | 0x01 : // sets LSB to 1
                                    newGreen & 0xfe;  // sets LSB to 0
                            break;
                        case 2:
                            newBlue = payload[bitCounter] ?
                                    newBlue | 0x01 : // sets LSB to 1
                                    newBlue & 0xfe;  // sets LSB to 0
                            break;
                    }
                }

                // Create a new color object
                final Color modified = new Color(newRed, newGreen, newBlue);

                // Replace the current pixel with the new color
                image.setRGB(i, j, modified.getRGB());

                // Uncomment to see changes in the RGB components
                //System.out.printf("%3d [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);
            }
        }
    }

    protected final boolean[][] decode(final BufferedImage image) {
        boolean[] payloadBits = new boolean[0];
        final boolean[] payloadSizeBits = new boolean[SIZE_LENGTH_BITS];

        for (int i = image.getMinX(), bitCounter = 0;
             i < image.getWidth() && bitCounter < payloadBits.length + payloadSizeBits.length;
             i++) {
            for (int j = image.getMinY();
                 j < image.getHeight() && bitCounter < payloadBits.length + payloadSizeBits.length;
                 j++) {
                final Color color = new Color(image.getRGB(i, j));
                final boolean redBit = ((color.getRed() & 0x1) != 0);
                final boolean greenBit = ((color.getGreen() & 0x1) != 0);
                final boolean blueBit = ((color.getBlue() & 0x1) != 0);

                for (byte rgb = 0; rgb < 3 && bitCounter < payloadBits.length + payloadSizeBits.length; rgb++, bitCounter++) {
                    switch (rgb) {
                        case 0:
                            readBit(bitCounter, redBit, payloadSizeBits, payloadBits);
                            break;
                        case 1:
                            readBit(bitCounter, greenBit, payloadSizeBits, payloadBits);
                            break;
                        case 2:
                            readBit(bitCounter, blueBit, payloadSizeBits, payloadBits);
                            break;
                    }

                    if (bitCounter == SIZE_LENGTH_BITS - 1) {
                        // read the size
                        final int length = key == null ?
                                ByteBuffer.wrap(getBytes(payloadSizeBits)).getInt() : // when not encrypting
                                ByteBuffer.wrap(getBytes(payloadSizeBits)).getInt() + IV_LENGTH; // when encrypting we need room for IV
                        payloadBits = new boolean[length * 8];
                    }
                }
            }
        }

        final boolean[][] result = new boolean[2][];
        result[0] = payloadSizeBits;
        result[1] = payloadBits;

        return result;
    }

    private void readBit(int bitCounter, boolean bit, boolean[] size, boolean[] payload) {
        if (bitCounter < SIZE_LENGTH_BITS) {
            size[bitCounter] = bit;
        } else {
            payload[bitCounter - SIZE_LENGTH_BITS] = bit;
        }
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
