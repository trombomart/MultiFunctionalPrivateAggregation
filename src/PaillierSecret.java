import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierSecret {

    private final BigInteger n;
    private final BigInteger n2;
    private final BigInteger g;
    private final BigInteger lambda;
    private final BigInteger mu;
    private final BigInteger phiN;

    public PaillierSecret() {
        BigInteger p = BigInteger.probablePrime(1024, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(1024, new SecureRandom());
        n = p.multiply(q);
        n2 = n.multiply(n);
        g = n.add(BigInteger.ONE);
        phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        lambda = Util.lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        mu = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).modInverse(n);
    }

    public BigInteger getPhiN() {
        return phiN;
    }

    public PaillierPublic getPublicKey() {
        return new PaillierPublic(n, n2, g);
    }

    public static BigInteger encrypt(PaillierPublic pk, BigInteger m, BigInteger r) {
        BigInteger g = pk.getG();
        BigInteger n = pk.getN();
        BigInteger n2 = pk.getN2();
        return g.modPow(m, n2).multiply(r.modPow(n, n2)).mod(n2);
    }

    public BigInteger decrypt(BigInteger c) {
        return c.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
    }



}
