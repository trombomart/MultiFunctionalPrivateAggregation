import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

public class MainHotel {

    private static ArrayList<Integer> values1;
    private static ArrayList<Integer> values2;

    public static void read(int amountOfUser) {
        values1 = new ArrayList<>();
        values2 = new ArrayList<>();
        try(BufferedReader in = new BufferedReader(new FileReader("C:\\Users\\marti\\Downloads\\archive\\Hotel_Reviews.csv"))) {
            in.readLine();
            String dataString;
            while ((dataString = in.readLine()) != null && values1.size() < amountOfUser) {
                String[] dataArray = dataString.split(",");
                float value1 = Float.parseFloat(dataArray[12]);
                double value2 = Double.parseDouble(dataArray[12]);
                if (value2 > 10) value2 = Math.round(value2 / 10);
                values1.add((int) Math.floor(value1 / 10));
                values2.add((int) value2);
            }
        }
            catch (IOException e) {
                System.out.println("File Read Error");
            }
    }


    public static void main(String[] args) {
        int amountOfUsers = 30;
        read(30);
        System.out.println("test");
    }
}
