import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierPublic {

    private final BigInteger n;
    private final BigInteger n2;
    private final BigInteger g;

    public PaillierPublic(BigInteger n, BigInteger n2, BigInteger g) {
        this.n = n;
        this.n2 = n2;
        this.g = g;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getN2() {
        return n2;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger generateR() {
        BigInteger r;
        do {
            r = new BigInteger(2048, new SecureRandom()).mod(n);
        } while(r.gcd(n).intValue() != 1);
        return r;
    }

}
