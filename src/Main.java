import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

public class Main {

    private static ArrayList<ArrayList<Integer>> data;

    public static void read(int amountOfValues) {
        data = new ArrayList<>();
        try(BufferedReader in = new BufferedReader(new FileReader("C:\\Users\\marti\\Downloads\\LD2011_2014.txt\\LD2011_2014.txt"))) {
            String nameString = in.readLine();
            String [] names = nameString.split(";");
            for(int i = 1; i < names.length; i++) {
                data.add(new ArrayList<>());
            }
            String dataString;
            while ((dataString = in.readLine()) != null) {
                dataString = dataString.replaceAll(",",".");
                String[] dataArray = dataString.split(";");
                for (int i = 1; i < dataArray.length; i++) {
                    int d = (int) Math.floor(Math.round(Float.valueOf(dataArray[i])) / 4);
                    if (d > amountOfValues - 2)
                        d = amountOfValues - 1;
                    data.get(i-1).add(d);
                }
            }
        }
        catch (IOException e) {
            System.out.println("File Read Error");
        }
    }

    public static void main(String[] args) {
        int amountOfValues = 238;
        int amountOfUsers = 370;
        int k = 3;
        read(amountOfValues);
        Aggregator aggregator = new Aggregator(amountOfUsers, amountOfValues, k);
        for (int i = 0; i < data.size(); i++) {
            aggregator.getUsers().get(i).setData(data.get(i));
        }
        aggregator.shareRandomness();
        BigInteger sum = aggregator.aggregate(0);
        ArrayList<Integer> counts = aggregator.decode(sum);

        for (int i = 0; i < amountOfValues; i++) {
            System.out.println("Value [" + i*4 + ", " + (i+1)*4 + ") is sent " + counts.get(i) + " times");
        }


    }

}
