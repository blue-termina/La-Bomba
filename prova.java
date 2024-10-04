import java.util.Scanner;
public class prova {
    public static void main(String[] args) {
        Scanner Scanner1 =new Scanner(System.in);
        System.out.println("in serusci un nome");
        int data=Scanner1.nextInt();
        if(data>=18)
        {  
            System.out.println("ha un documento?");
            Scanner Scanner2 =new Scanner(System.in);
            String utente =Scanner2.nextLine();
            if (utente.equals("si"))
            {
                System.out.println("entra");
            }else{
                System.out.println("non piu entrare");
            }
        }else
        {
            System.out.println("sei minorenne non piu entrare");
        }
    }
}