import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Objects;

public class ProofPlainTextEquality {

    private final BigInteger z;
    private final BigInteger ui;
    private final BigInteger uj;
    private final BigInteger vi;
    private final BigInteger vj;
    private final BigInteger ni;
    private final BigInteger ni2;
    private final BigInteger gi;
    private final BigInteger nj;
    private final BigInteger nj2;
    private final BigInteger gj;

    public ProofPlainTextEquality(PaillierPublic pki, PaillierPublic pkj, BigInteger ri, BigInteger rj, BigInteger m) {
        ni = pki.getN();
        ni2 = pki.getN2();
        gi = pki.getG();
        nj = pkj.getN();
        nj2 = pkj.getN2();
        gj = pkj.getG();

        BigInteger rho = new BigInteger(2048, new SecureRandom());
        BigInteger si = pki.generateR();
        BigInteger sj = pkj.generateR();

        ui = gi.modPow(rho, ni2).multiply(si.modPow(ni, ni2)).mod(ni2);
        uj = gj.modPow(rho, nj2).multiply(sj.modPow(nj, nj2)).mod(nj2);

        ArrayList<BigInteger> byteList = new ArrayList<>();
        byteList.add(ui);
        byteList.add(uj);
        byte[] bytes = Util.combineByteArrays(byteList);
        BigInteger e = new BigInteger(Objects.requireNonNull(Util.SHA256(bytes)));

        z = rho.add(m.multiply(e));

        vi = si.multiply(ri.modPow(e, ni)).mod(ni);
        vj = sj.multiply(rj.modPow(e, nj)).mod(nj);
    }

    public boolean verify(BigInteger ci, BigInteger cj) {
        ArrayList<BigInteger> byteList = new ArrayList<>();
        byteList.add(ui);
        byteList.add(uj);
        byte[] bytes = Util.combineByteArrays(byteList);
        BigInteger e = new BigInteger(Objects.requireNonNull(Util.SHA256(bytes)));

        BigInteger check1a = gi.modPow(z, ni2).multiply(vi.modPow(ni, ni2)).mod(ni2);
        BigInteger check1b = ui.multiply(ci.modPow(e, ni2)).mod(ni2);

        BigInteger check2a = gj.modPow(z, nj2).multiply(vj.modPow(nj, nj2)).mod(nj2);
        BigInteger check2b = uj.multiply(cj.modPow(e, nj2)).mod(nj2);

        return check1a.equals(check1b) && check2a.equals(check2b);
    }

}
