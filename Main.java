import java.math.BigInteger;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) {
        int amountOfValues = 4;
        Aggregator aggregator = new Aggregator(5, amountOfValues);
        aggregator.shareRandomness();
        BigInteger sum = aggregator.aggregate();
        ArrayList<Integer> counts = aggregator.decode(sum);

        for (int i = 0; i < amountOfValues; i++) {
            System.out.println("Value " + i + " is sent " + counts.get(i) + " times");
        }


    }

}
