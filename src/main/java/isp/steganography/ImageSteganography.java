package isp.steganography;

import javafx.util.Pair;

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
     * GCM IV length in bytes
     */
    protected static final int IV_LENGTH = 12;

    /**
     * The number of bits representing the payload size
     */
    protected static final int SIZE_LENGTH_BITS = 32;

    /**
     * GCM MAC size in bytes
     */
    protected static final int GMAC_LENGTH = 16;

    /**
     * Key used for encryption
     */
    protected final Key key;

    protected final BufferedImage image;

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

    public void encode(final String outFile, final byte[] payload) throws IOException {
        if (key == null) {
            doEncode(outFile, payload);
        } else {
            doEncryptAndEncode(outFile, payload);
        }
    }

    /**
     * Encodes the payload and saves the image into given filename
     *
     * @param outFile The filename of the created steganogram
     * @param payload The payload to be encoded
     * @throws IOException when the image cannot be saved into given file
     */
    protected void doEncode(final String outFile, final byte[] payload) throws IOException {
        // determine the size of the payload and convert it to bits
        final boolean[] payloadSizeBits = getBits(ByteBuffer.allocate(4).putInt(payload.length).array());
        // convert the payload into bits
        final boolean[] payloadBits = getBits(payload);
        // merge the two arrays
        final boolean[] entirePayload = Arrays.copyOf(payloadSizeBits, payloadSizeBits.length + payloadBits.length);
        System.arraycopy(payloadBits, 0, entirePayload, payloadSizeBits.length, payloadBits.length);

        // encode the bits into image
        encode(entirePayload, image);

        // save the modified image into outFile
        ImageIO.write(image, "png", new File(outFile));
    }

    /**
     * Encrypts and encodes given payload onto the image that has previously been loaded,
     * and then writes the modified image to the given file.
     * <p>
     * The encoded data has the following structure:
     * <ol>
     * <li>The first 32 bits represent an integer that denotes the size of the payload:</li>
     * <li>The remaining bits denote the payload:</li>
     * <ul>
     * <li>The first 96 bits (12 bytes) of the payload is not encrypted; they represent the IV that was used to encrypt the payload.</li>
     * <li>The remaining bits denote the encrypted part;</li>
     * <li>The last 128 bits of the payload denote the Galois MAC.</li>
     * </ul>
     * </ol>
     * The bytes that denote the IV and the size of the payload are included in the computation of the GMAC. Function Cipher.updateAAD is used to authenticated these bytes.
     *
     * @param outFile The filename of the steganogram
     * @param payload The byte[] to be encoded
     */
    protected void doEncryptAndEncode(final String outFile, final byte[] payload) throws IOException {
        try {
            // Encryption with GCM. This requires JAVA 8.
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            /* The size of the encoded payload is the size of the actual payload plus the
             * size of the Galois MAC (GMAC). Note the size of the cipher text is the
             * same as the size of the plaint text, since GCM is in effect a stream cipher. */
            final byte[] payloadSize = ByteBuffer.allocate(4).putInt(payload.length + GMAC_LENGTH).array();

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

            // convert bytes to bits and concatenate them into a single array
            final boolean[] payloadSizeBits = getBits(payloadSize);
            final boolean[] payloadBits = getBits(ivAndPayload);
            final boolean[] entirePayload = Arrays.copyOf(payloadSizeBits, payloadSizeBits.length + payloadBits.length);
            System.arraycopy(payloadBits, 0, entirePayload, payloadSizeBits.length, payloadBits.length);

            // encode the bits into image
            encode(entirePayload, image);

            // save the modified image to outFile
            ImageIO.write(image, "png", new File(outFile));
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException |
                InvalidKeyException |
                IllegalBlockSizeException |
                BadPaddingException e) {
            System.err.printf("Exception: %s%n", e.getLocalizedMessage());
            throw new IllegalStateException(e);
        }
    }

    /**
     * Encodes given array of bits into given image. The algorithm modifies the
     * least significant bit of each color component of each image pixel.
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
                // System.out.printf("[%d, %d]: %s -> %s%n", i, j, original, modified);
            }
        }
    }

    /**
     * Decodes the payload from loaded steganogram.
     * <p>
     * If the key has been set, the decryption is applied beforehand.
     *
     * @return
     */
    public byte[] decode() {
        // decode the image
        final Pair<boolean[], boolean[]> decoded = decode(image);

        final byte[] size = getBytes(decoded.getKey());
        final byte[] payload = getBytes(decoded.getValue());

        // if there's no key, we're done
        if (key == null) {
            return payload;
        } else {
            // we have to decrypt first
            try {
                // The first 12 bytes represent the IV
                final byte[] iv = Arrays.copyOfRange(payload, 0, IV_LENGTH);

                // Set the GCM parameters
                final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(8 * GMAC_LENGTH, iv);

                // set up the cipher
                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

                // The GMAC is computed over IV
                cipher.updateAAD(iv);

                // The GMAC is computed over size, too
                cipher.updateAAD(size);

                // the encrypted payload is from the 16th byte onwards
                final byte[] encryptedPayload = Arrays.copyOfRange(payload, IV_LENGTH, payload.length);

                // decrypt and return result
                return cipher.doFinal(encryptedPayload);
            } catch (BadPaddingException |
                    IllegalBlockSizeException |
                    NoSuchAlgorithmException |
                    NoSuchPaddingException |
                    InvalidKeyException |
                    InvalidAlgorithmParameterException e) {
                System.err.printf("Exception: %s%n", e.getLocalizedMessage());
                throw new IllegalStateException(e);
            }
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
     * Decodes given image and returns two bit (boolean) arrays, where the first
     * denotes the size of the encoded payload and the second the payload itself.
     *
     * @param image The steganogram
     * @return The decoded payload as two dimensional array
     */
    protected final Pair<boolean[], boolean[]> decode(final BufferedImage image) {
        boolean[] payloadBits = new boolean[0];
        final boolean[] payloadSizeBits = new boolean[SIZE_LENGTH_BITS];

        for (int i = image.getMinX(), bitCounter = 0;
             i < image.getWidth() && bitCounter < payloadBits.length + payloadSizeBits.length;
             i++) {
            for (int j = image.getMinY();
                 j < image.getHeight() && bitCounter < payloadBits.length + payloadSizeBits.length;
                 j++) {
                final Color color = new Color(image.getRGB(i, j));

                for (byte rgb = 0;
                     rgb < 3 && bitCounter < payloadBits.length + payloadSizeBits.length;
                     rgb++, bitCounter++) {
                    switch (rgb) {
                        case 0:
                            readBit(color.getRed(), bitCounter, payloadSizeBits, payloadBits);
                            break;
                        case 1:
                            readBit(color.getGreen(), bitCounter, payloadSizeBits, payloadBits);
                            break;
                        case 2:
                            readBit(color.getBlue(), bitCounter, payloadSizeBits, payloadBits);
                            break;
                    }

                    // After reading the first 32 bits ...
                    if (bitCounter == SIZE_LENGTH_BITS - 1) {
                        // ... we can determine the size of the payload.
                        final int length = key == null ?
                                // If the payload has not been encrypted, we're done.
                                ByteBuffer.wrap(getBytes(payloadSizeBits)).getInt() :
                                // If the payload was encrypted, we account for the length of the IV
                                ByteBuffer.wrap(getBytes(payloadSizeBits)).getInt() + IV_LENGTH;

                        // allocate spacae for  the payload
                        payloadBits = new boolean[length * 8];
                    }
                }
            }
        }

        // return the result as a pair
        return new Pair<>(payloadSizeBits, payloadBits);
    }

    /**
     * The method reads the LSB from given color and writes it to either the
     * size or the payload bit array, depending on the value of the bitCounter.
     *
     * @param color      the color of the pixel
     * @param bitCounter the number of the bit that is currently being processed
     * @param size       the array of bits representing the size of the payload
     * @param payload    the array of bits representing the payload
     */
    protected void readBit(int color, int bitCounter, boolean[] size, boolean[] payload) {
        final boolean bit = ((color & 0x1) != 0);

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
