import java.util.Scanner;

public class calcolatrice {
    public static void main(String[] args) {
        Scanner Scanner = new Scanner(System.in);
        System.out.print("inserire primo numero\n");
        int numero1 = Scanner.nextInt();
        System.out.print("inserire secondo numrero\n");
        int numero2 = Scanner.nextInt();
        int somma = numero1 + numero2;
        int sotrazione = numero1 - numero2;
        int divisione = numero1 / numero2;
        int moltiplicazione = numero1 * numero2;
        System.out.println("la somma è:  " + somma);
        System.out.println("la sotrazionea è:   " + sotrazione);
        System.out.println("la division: è:  " + divisione);
        System.out.println("la moltiplicazione: è: " + moltiplicazione);

    }
}