import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Objects;

public class ProofSetMembership {

    private final BigInteger gA;
    private final BigInteger nA2;
    private final BigInteger gS;
    private final BigInteger hA;
    private final BigInteger B;
    private final BigInteger B1;
    private final BigInteger D;
    private final BigInteger c1;
    private final BigInteger D1;
    private final BigInteger s1;
    private final BigInteger s2;
    private final BigInteger s3;
    private final BigInteger h;

    public ProofSetMembership(PaillierPublic pkA, BigInteger c, BigInteger ai, BigInteger sigmai, BigInteger gS, BigInteger hA, BigInteger s_, BigInteger si) {
        gA = pkA.getG();
        BigInteger nA = pkA.getN();
        nA2 = pkA.getN2();
        this.gS = gS;
        this.hA = hA;

        BigInteger l = new BigInteger(2048, new SecureRandom()).mod(nA);
        BigInteger l_ = new BigInteger(2048, new SecureRandom()).mod(nA);
        BigInteger a_ = new BigInteger(2048, new SecureRandom()).mod(nA);

        B = sigmai.modPow(l, nA2);
        B1 = B.modInverse(nA2);
        D = B1.modPow(ai, nA2).multiply(gS.modPow(l, nA2)).mod(nA2);
        c1 = gA.modPow(a_,nA2).multiply(hA.modPow(s_, nA2)).mod(nA2);
        D1 = B1.modPow(a_, nA2).multiply(gS.modPow(l_, nA2)).mod(nA2);

        ArrayList<BigInteger> byteList = new ArrayList<>();
        byteList.add(c);
        byteList.add(B);
        byteList.add(D);
        byte[] bytes = Util.combineByteArrays(byteList);
        h = new BigInteger(Objects.requireNonNull(Util.SHA256(bytes)));

        s1 = a_.add(h.multiply(ai)).mod(nA);
        s2 = s_.add(h.multiply(si));
        s3 = l_.add(h.multiply(l)).mod(nA);
    }

    public boolean verify(BigInteger c, BigInteger x) {
        BigInteger D_ = B.modPow(x, nA2);

        ArrayList<BigInteger> byteList = new ArrayList<>();
        byteList.add(c);
        byteList.add(B);
        byteList.add(D_);
        byte[] bytes = Util.combineByteArrays(byteList);
        BigInteger h = new BigInteger(Objects.requireNonNull(Util.SHA256(bytes)));

        BigInteger c1_ = gA.modPow(s1, nA2).multiply(hA.modPow(s2, nA2)).multiply(c.modInverse(nA2).modPow(h, nA2)).mod(nA2);
        BigInteger D1_ = B1.modPow(s1, nA2).multiply(gS.modPow(s3, nA2)).multiply(D_.modInverse(nA2).modPow(h, nA2)).mod(nA2);

        return D.equals(D_) && c1.equals(c1_) && D1.equals(D1_);

    }

    public BigInteger getH(){
        return h;
    }

    public BigInteger getS2() {
        return s2;
    }

}
