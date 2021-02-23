import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

public class User {

    private PaillierSecret ski;
    private PaillierPublic pki;
    private BigInteger ni;
    private BigInteger ni2;
    private BigInteger gi;
    private BigInteger phiNi;

    private ArrayList<BigInteger> coefficients;
    private ArrayList<BigInteger> signatures;
    private BigInteger a;
    private BigInteger sigma;

    private PaillierPublic pkA;
    private BigInteger nA;
    private BigInteger nA2;
    private BigInteger gA;
    private BigInteger hA;
    private BigInteger gS;

    private int ID;

    private ArrayList<PaillierPublic> pk;

    private ArrayList<BigInteger> randomness_Out;
    private ArrayList<BigInteger> randomness_In;
    private ArrayList<BigInteger> randomness_Out_Cipher;
    private ArrayList<BigInteger> randomness_In_Cipher;
    private ArrayList<BigInteger> randomness_Out_Random;
    private ArrayList<BigInteger> randomness_Out_Cipher_Own;
    private ArrayList<BigInteger> randomness_Out_Random_Own;

    private BigInteger nA_Ciph;
    private BigInteger nA_Ciph_Own;
    private BigInteger nA_Random;
    private BigInteger nA_Random_Own;
    private BigInteger h;
    private BigInteger s2;
    private BigInteger s2_Random;
    private BigInteger s2_Random_Own;

    public BigInteger c;
    public BigInteger s;

    public User(int ID, PaillierPublic pkA, ArrayList<BigInteger> coefficients, BigInteger hA, ArrayList<BigInteger> signatures, BigInteger gS) {
        this.ID = ID;

        ski = new PaillierSecret();
        pki = ski.getPublicKey();
        ni = pki.getN();
        ni2 = pki.getN2();
        gi = pki.getG();
        phiNi = ski.getPhiN();

        this.coefficients = coefficients;
        this.signatures = signatures;

        this.pkA = pkA;
        nA = pkA.getN();
        nA2 = pkA.getN2();
        gA = pkA.getG();
        this.hA = hA;
        this.gS = gS;
    }

    public PaillierPublic getPK() {
        return pki;
    }

    public void setPk(ArrayList<PaillierPublic> pk) {
        this.pk = pk;
    }

    public void generateRandomness() {
        randomness_Out = new ArrayList<>();
        randomness_Out_Cipher = new ArrayList<>();
        randomness_Out_Random = new ArrayList<>();
        randomness_Out_Cipher_Own = new ArrayList<>();
        randomness_Out_Random_Own = new ArrayList<>();
        randomness_In = new ArrayList<>();
        randomness_In_Cipher = new ArrayList<>();
        for(int j = 0; j < pk.size(); j++) {
            PaillierPublic pkj = pk.get(j);
            BigInteger nj = pk.get(j).getN();
            BigInteger nj2 = pk.get(j).getN2();
            BigInteger gj = pk.get(j).getG();
            if(j == ID) {
                randomness_Out.add(BigInteger.ZERO);
                randomness_Out_Random.add(BigInteger.ONE);
                randomness_Out_Cipher.add(BigInteger.ONE);
                randomness_Out_Random_Own.add(BigInteger.ONE);
                randomness_Out_Cipher_Own.add(BigInteger.ONE);
            } else {
                randomness_Out.add(new BigInteger(2048, new SecureRandom()).mod(nj));
                randomness_Out_Random.add(pkj.generateR());
                randomness_Out_Cipher.add(gj.modPow(randomness_Out.get(j), nj2).multiply(randomness_Out_Random.get(j).modPow(nj, nj2)).mod(nj2));
                randomness_Out_Random_Own.add(pki.generateR());
                randomness_Out_Cipher_Own.add(gi.modPow(randomness_Out.get(j), ni2).multiply(randomness_Out_Random_Own.get(j).modPow(ni, ni2)).mod(ni2));
            }
        }
    }

    public ArrayList<BigInteger> getRandomness() {
        return randomness_Out_Cipher;
    }

    public ArrayList<BigInteger> getRandomnessOwn() {
        return randomness_Out_Cipher_Own;
    }

    public ArrayList<ProofPlainTextEquality> getRandomnessEquality() {
        ArrayList<ProofPlainTextEquality> proofs = new ArrayList<>();
        for (int j = 0; j < pk.size(); j++) {
            if(j != ID)
                proofs.add(new ProofPlainTextEquality(pki, pk.get(j), randomness_Out_Random_Own.get(j), randomness_Out_Random.get(j), randomness_Out.get(j)));
            else
                proofs.add(null);
        }
        return proofs;
    }

    public void receiveRandomness(BigInteger c) {
        randomness_In_Cipher.add(c);
        BigInteger r = ski.decrypt(c);
        randomness_In.add(r);
    }

    public void generateShare() {
        s = nA;
        for (BigInteger r: randomness_Out)
            s = s.add(r);
        for (BigInteger r: randomness_In)
            s = s.subtract(r);
    }

    public void generateCipher(BigInteger m) {
        generateShare();
        c = gA.modPow(m, nA2).multiply(hA.modPow(s, nA2)).mod(nA2);
    }

    public BigInteger sendCipher() {
        int message = (int) (Math.random()*coefficients.size()%coefficients.size());
        a = coefficients.get(message);
        sigma = signatures.get(message);
        System.out.println("User " + ID + " has coefficient " + a);
        generateCipher(a);
        return c;
    }

    public ProofSetMembership sendProofMember() {
        BigInteger s_ = BigInteger.ZERO;
        for(BigInteger x: randomness_Out) {
            s_ = s_.add(x);
        }
        ProofSetMembership proof = new ProofSetMembership(pkA, c, a, sigma, gS, hA, s_, s);
        h = proof.getH();
        s2 = proof.getS2();
        return proof;
    }

    public BigInteger sendNaCipher() {
        nA_Random = pkA.generateR();
        nA_Ciph = PaillierSecret.encrypt(pkA, nA, nA_Random);
        return nA_Ciph;
    }

    public BigInteger sendNaCipherOwn() {
        nA_Random_Own = pki.generateR();
        nA_Ciph_Own = PaillierSecret.encrypt(pki, nA, nA_Random_Own);
        return nA_Ciph_Own;
    }

    public ProofPlainTextEquality sendProofNaEquality() {
        return new ProofPlainTextEquality(pki, pkA, nA_Random_Own, nA_Random, nA);
    }

    public BigInteger sendS2Own() {
        BigInteger s2_ciph_own = nA_Ciph_Own;
        for (BigInteger x: randomness_Out_Cipher_Own)
            s2_ciph_own = s2_ciph_own.multiply(x);
        for (BigInteger x: randomness_In_Cipher)
            s2_ciph_own = s2_ciph_own.multiply(x.modInverse(ni2));
        s2_ciph_own = s2_ciph_own.modPow(h, ni2);
        for (BigInteger x: randomness_Out_Cipher_Own)
            s2_ciph_own = s2_ciph_own.multiply(x);

        s2_Random_Own = s2_ciph_own.multiply(BigInteger.ONE.subtract(s2.multiply(ni))).mod(ni2).modPow(ni.modInverse(phiNi), ni);
        return s2_ciph_own;
    }

    public BigInteger sendS2() {
        s2_Random = pkA.generateR();
        return PaillierSecret.encrypt(pkA, s2, s2_Random);
    }

    public ProofPlainTextEquality sendProofS2Equality() {
        return new ProofPlainTextEquality(pki, pkA, s2_Random_Own, s2_Random, s2);
    }

}
