
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.Scanner;

public class Sender extends RSA_keygen {

    public static void main(String[] args) throws Exception {

        String yPublicKey = "YPublic.key";
        String symKey = "symmetric.key";
        String keyedMes = "message.kmk";
        String filename = getMessage();
        keyedMessage(symKey, filename);
        calcMessageDigest(keyedMes);
        AES_Encrypt(symKey,filename);
        SymKey_Encrypt(yPublicKey, symKey);

//        byte[] message = ReadAllBytes(keyedMes);
//        String s = new String(message);
//        System.out.println(s);

    }

    public static byte[] ReadAllBytes(String filename) throws IOException {
        File file = new File(filename);
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        return fileBytes;
    }


    private static void writeBytes(byte[] byteFile, String fileDest) {
        try (FileOutputStream os = new FileOutputStream(fileDest)) {
            os.write(byteFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private static void appendBytes(byte[] byteFile, String fileDest) {
        try (FileOutputStream os = new FileOutputStream(fileDest, true)) {
            os.write(byteFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private static void SymKey_Encrypt(String PublicKey, String SymmetricKey) throws Exception {
        SecureRandom random = new SecureRandom();
        Key yPubKey = readPubKeyFromFile(PublicKey);
        byte[] symKey = ReadAllBytes(SymmetricKey);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, yPubKey, random);
        byte[] cipherText = cipher.doFinal(symKey);
        writeBytes(cipherText, "kxy.rsacipher");
    }



    private static void keyedMessage(String SymKey, String Message) throws Exception {
        byte[] symKey = ReadAllBytes(SymKey);
        byte[] message = ReadAllBytes(Message);
        String dest = "message.kmk";
        writeBytes(symKey, dest);
        appendBytes(message, dest);
        appendBytes(symKey, dest);
    }



    public static String calcMessageDigest(String File) throws Exception {
        int BUFFER_SIZE = 32 * 1024;
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(File));
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, messageDigest);
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do{
            i = in.read(buffer, 0, BUFFER_SIZE);
        }while (i == BUFFER_SIZE);
        messageDigest = in.getMessageDigest();
        in.close();
        byte[] hash = messageDigest.digest();
        System.out.println("*** KEYED HASH MAC: ***");

        for (int k=0, j=0; k<hash.length; k++, j++) {
            System.out.format("%2X ", hash[k]) ;
            if (j >= 15) {
                System.out.println("\n");
                j=-1;
            }
        }
        System.out.println("");
        writeBytes(hash, "message.khmac");
        return new String(hash);
    }



    private static byte[] AES_Encrypt(String SymKey, String Message) throws Exception{
        String IV ="JennyIGot8675309";
        byte[] message = ReadAllBytes(Message);
        byte[] symKey = ReadAllBytes(SymKey);

        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));

        byte[] cipherText =  cipher.doFinal(message);
        writeBytes(cipherText,"message.aescipher");
        return cipherText;
    }

    public static String getMessage() throws IOException {
        Scanner userInput = new Scanner(System.in);
        System.out.println("Input the name of the message file: ");
        String message = userInput.nextLine();
        while(message == null){
            System.out.println("Input the name of the message file: ");
            message = userInput.nextLine();
        }
        return message;
    }
}
