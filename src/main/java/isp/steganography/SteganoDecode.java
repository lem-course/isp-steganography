package isp.steganography;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.imageio.ImageIO;

/**
 * EXERCISE:
 * <p/>
 * - E1. Ensure initial offset when encoding LSB bits
 * - E2. Ensure Implement changing distance between LSB bits
 * - E3. Implement EOF auto-detection
 * - E4. Switch between RGB values
 * - E5. Use encryption (e.g. AES) to provide message secrecy
 * - E6. Use HMAC to provide message authenticity and data integrity
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 9. 12. 2013
 */
public class SteganoDecode {

    private final int messageLen;
    private final boolean[] bitMessage;

    private final BufferedImage src;

    private int MINX = 0;
    private int MINY = 0;
    private int WIDTH = 0;
    private int HEIGHT = 0;

    public SteganoDecode(String srcFile, int messageLen) throws IOException {

        this.messageLen = messageLen; // Fixed message size in bytes (E3. Implement EOF auto-detection)

        // Load the Image
        this.src = ImageIO.read(new File(srcFile));
        this.MINX = src.getMinX();
        this.MINY = src.getMinY();
        this.WIDTH = src.getWidth();
        this.HEIGHT = src.getHeight();

        // Steganogram bit sequence
        this.bitMessage = new boolean[messageLen * 8];

        // Decode Bits from the Image
        doDecode();

        // Convert Bits to Bytes and finally to String and print out
        String steganoMessage = new String(getByteSequence(this.bitMessage, this.messageLen));
        System.out.println(steganoMessage);
    }

    private byte[] getByteSequence(boolean[] x, int mLenInBytes) {

        // Create the byte sequence to store steganogram
        byte[] messageBytes = new byte[mLenInBytes];

        // Interate over known message size
        for (int i = 0; i != mLenInBytes; i++) {
            byte y = 0x00;
            for (int j = 0; j != 8; j++) {
                // Retrieve individual bits from the steganogram
                // and store them to appropriate byte position
                y |= (x[8 * i + j] ? (byte) 0x01 : (byte) 0x00) << j;
            }
            messageBytes[i] = y; // Store the retrieved value in the byte sequence
        }
        return messageBytes;
    }

    private void doDecode() {
        // Iterate from min.x to max.x
        for (int i = MINX, cnt = 0; i != WIDTH; i++) {
            // Iterate from min.y to max.y
            for (int j = MINY; j != HEIGHT; j++) {

                // Get current pixel and conver to Alpha, Red, Green, Blue
                int pixel = this.src.getRGB(i, j);
                int[] argb = convPixel2ARGB(pixel);

                // Decode current red pixel LSB
                this.bitMessage[cnt] = ((argb[1] & 0x1) != 0);

                // Return if done
                cnt++;
                if (this.messageLen * 8 == cnt)
                    return;
            }
        }
    }

    private int[] convPixel2ARGB(int pixel) {
        // Parse
        int alpha = (pixel >> 24) & 0xff;
        int red = (pixel >> 16) & 0xff;
        int green = (pixel >> 8) & 0xff;
        int blue = (pixel) & 0xff;
        int[] retVal = {alpha, red, green, blue};
        return retVal;
    }

    public static void main(String[] args) throws IOException {
        SteganoDecode sd = new SteganoDecode("slike/Steganogram.png", 20);
    }
}
