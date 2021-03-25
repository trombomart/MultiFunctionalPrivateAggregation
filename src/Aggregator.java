import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;

public class Aggregator {

    private ArrayList<BigInteger> coefficients;
    private ArrayList<BigInteger> signatures;
    private ArrayList<User> users;
    private ArrayList<PaillierPublic> pk;

    private final BigInteger x;
    private final PaillierPublic pkA;
    private final PaillierSecret skA;
    private final BigInteger nA;
    private final BigInteger nA2;
    private final BigInteger gS;
    private final BigInteger hA;

    private HashMap<Integer, ArrayList<BigInteger>> randomness;
    private HashMap<Integer, ArrayList<BigInteger>> randomnessOwn;

    private final int k;


    public Aggregator(int amountOfUsers, int amountOfValues, int k) {
        this.k = k;
        skA = new PaillierSecret();
        pkA = skA.getPublicKey();
        nA = pkA.getN();
        nA2 = pkA.getN2();
        gS = nA.add(BigInteger.ONE);
        hA = nA.add(BigInteger.ONE);
        x = new BigInteger(2048, new SecureRandom()).mod(nA);

        generateCoefficients(amountOfValues, amountOfUsers);
        generateUsers(amountOfUsers);
    }

    public ArrayList<User> getUsers() {
        return users;
    }

    public void generateUsers(int amountOfUsers) {
        users = new ArrayList<>();
        pk = new ArrayList<>();
        for(int i = 0; i < amountOfUsers; i++) {
            users.add(new User(i, pkA, coefficients, hA, signatures, gS));
            pk.add(users.get(i).getPK());
        }
        for(int i = 0; i < amountOfUsers; i++) {
            ArrayList<PaillierPublic> tempPK = new ArrayList<>();
            for (int j = 1; j <= k; j++) {
                tempPK.add(users.get((i+j)%amountOfUsers).getPK());
            }
            users.get(i).setPk(tempPK);
        }

    }

    public void generateCoefficients(int amountOfValues, int amountOfUsers) {
        coefficients = new ArrayList<>();
        signatures = new ArrayList<>();
        BigInteger currentCoefficient;
        for (int i = 0; i < amountOfValues; i++) {
            if(i == 0)
                currentCoefficient = BigInteger.ONE;
            else
                currentCoefficient = coefficients.get(i-1).multiply(BigInteger.valueOf(amountOfUsers)).add(BigInteger.ONE);
            while(!setUpSignature(currentCoefficient)) {
                currentCoefficient = currentCoefficient.add(BigInteger.ONE);
            }
            if (currentCoefficient.multiply(BigInteger.valueOf(amountOfUsers)).compareTo(nA) > 0) {
                System.out.println("Too many coefficients: " + i);
                System.exit(-1);
            }
            coefficients.add(currentCoefficient);
        }
        System.out.println("Coefficients generated");
    }

    public boolean setUpSignature(BigInteger coefficient) {
        try {
            BigInteger exp = x.add(coefficient).modInverse(nA);
            BigInteger signature = gS.modPow(exp, nA2);
            signatures.add(signature);
            return true;
        } catch (ArithmeticException e) {
            return false;
        }
    }

    public void shareRandomness() {
        randomness = new HashMap<>();
        randomnessOwn = new HashMap<>();
        for (int i = 0; i < users.size(); i++) {
            users.get(i).generateRandomness();
            randomness.put(i, new ArrayList<>());
        }
        for (int i = 0; i < users.size(); i++) {
            ArrayList<BigInteger> rOwn = new ArrayList<>();
            ArrayList<BigInteger> ci = users.get(i).getRandomnessOwn();
            ArrayList<BigInteger> cj = users.get(i).getRandomness();
            ArrayList<ProofPlainTextEquality> proofs = users.get(i).getRandomnessEquality();
            boolean valid;
            for (int j = 0; j < k; j++) {
                if (i != j) {
                    valid = proofs.get(j).verify(ci.get(j), cj.get(j));
                    if (!valid) {
                        System.out.println("Verification randomness fails for users " + i + " and " + (i+j+1)%users.size());
                        break;
                    }
                    rOwn.add(ci.get(j));
                    randomness.get((i+j+1)%users.size()).add(cj.get(j));
                    users.get((i+j+1)%users.size()).receiveRandomness(cj.get(j));
                }
            }
            randomnessOwn.put(i, rOwn);
        }
    }

    public boolean verify(BigInteger c, int ID, User user) {
        boolean valid;
        ProofSetMembership proofMember = user.sendProofMember();
        valid = proofMember.verify(c, x);

        BigInteger nA_Cipher_A = user.sendNaCipher();
        BigInteger nA_Cipher_i = user.sendNaCipherOwn();
        ProofPlainTextEquality proofNa = user.sendProofNaEquality();
        valid = valid && proofNa.verify(nA_Cipher_i, nA_Cipher_A);

        BigInteger h = proofMember.getH();
        BigInteger s2 = proofMember.getS2();

        BigInteger s2_ciph_i = nA_Cipher_i;
        for (BigInteger x: randomnessOwn.get(ID))
            s2_ciph_i = s2_ciph_i.multiply(x);
        for (BigInteger x: randomness.get(ID))
            s2_ciph_i = s2_ciph_i.multiply(x.modInverse(pk.get(ID).getN2()));
        s2_ciph_i = s2_ciph_i.modPow(h, pk.get(ID).getN2());
        for (BigInteger x: randomnessOwn.get(ID))
            s2_ciph_i = s2_ciph_i.multiply(x);

        BigInteger s2_ciph_i_ = user.sendS2Own();
        valid = valid && s2_ciph_i.equals(s2_ciph_i_);

        BigInteger s2_ciph_A = user.sendS2();
        valid = valid && s2.mod(nA).equals(skA.decrypt(s2_ciph_A));

        ProofPlainTextEquality proofS2 = user.sendProofS2Equality();
        valid = valid && proofS2.verify(s2_ciph_i, s2_ciph_A);


        return valid;
    }

    public BigInteger aggregate(int round) {
        BigInteger c = BigInteger.ONE;
        for (int i = 0; i < users.size(); i++) {
            BigInteger ci = users.get(i).sendCipher(round);
            c = c.multiply(ci);
            if (!verify(ci, i, users.get(i)))
                System.out.println("Invalid ciphertext user " + i);
        }
        return skA.decrypt(c);
    }

    public ArrayList<Integer> decode(BigInteger sum) {
        ArrayList<Integer> counts = new ArrayList<>();
        for (int i = 0; i < coefficients.size(); i++) {
            counts.add(0);
        }
        for (int i = coefficients.size()-1; i >= 0; i--) {
            BigInteger temp = sum.mod(coefficients.get(i));
            counts.set(i, sum.subtract(temp).divide(coefficients.get(i)).intValue());
            sum = temp;
        }
        return counts;
    }

}
