import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
public class bot{
    public static void main(String[]  args){
        Scanner Scanner=new Scanner(System.in);
        System.out.println("quale musica ti piace ?");
        String utente=Scanner.next();
        List<String>  musica=new ArrayList<>();
        char lista[]={"21","no","34"};
        musica.add("pop");
        musica.add("classica");
        musica.add("roock");
        System.out.print("quale stile ti piace?"+musica);
        if (musica.contains(utente)) 
        {
            System.out.println("Il genere Rock è presente nella lista.");
            System.out.println("ti consigli dei prani"+"ma ti no"+"sarremo");
        } else {
            System.out.println("Il genere Rock non è presente nella lista.");
        }

        
    }  
}
 