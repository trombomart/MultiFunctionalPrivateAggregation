import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Util {

    public static BigInteger lcm(BigInteger s, BigInteger s1) {
        return s.multiply(s1).divide(s.gcd(s1));
    }

    public static byte[] SHA256 (byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(bytes);
        } catch(NoSuchAlgorithmException e) {
            System.out.println(e);
        }
        return null;
    }

    public static byte[] combineByteArrays(ArrayList<BigInteger> list) {
        int currentLength = 0;
        int totalLength = 0;
        for (BigInteger i: list) {
            totalLength += i.toByteArray().length;
        }
        byte[] bytes = new byte[totalLength];
        for (BigInteger i: list) {
            byte[] current = i.toByteArray();
            System.arraycopy(current, 0, bytes, currentLength, current.length);
            currentLength += current.length;
        }
        return bytes;
    }

}
