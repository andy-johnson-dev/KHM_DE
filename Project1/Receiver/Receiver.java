import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.DigestInputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

public class Receiver extends RSA_keygen {
    public static void main(String[] args) throws Exception {
        String saveFile;
        String yPrivKey = "YPrivate.key";
        String yPubKey = "YPublic.key";
        String symKeyCipher = "kxy.rsacipher";
        String hmacMessage = "message.khmac";
        String cipherMessage = "message.aescipher";
        String decryptSymKey = "decryptedSym.key";
        String mess2 = "message2.kmk";


        saveFile = getInput();
        SymKey_Decrypt(yPrivKey, symKeyCipher);
        AES_Decrypt(cipherMessage,"decryptedSym.key", saveFile);
        appendBytes(ReadAllBytes(decryptSymKey), "message2.kmk");

        byte[] HMACmessCalc = calcMessageDigest(mess2);
        byte[] HMACmessage = ReadAllBytes(hmacMessage);


        if(Arrays.equals(HMACmessCalc, HMACmessage)){
            System.out.println("EQUAL");
        }
        else{System.out.println("NOT EQUAL");}


        System.out.println("digit digest (hash value):");
        for (int k=0, j=0; k<HMACmessCalc.length; k++, j++) {
            System.out.format("%2X ", HMACmessCalc[k]) ;
            if (j >= 15) {
                System.out.println("\n");
                j=-1;
            }
        }
        System.out.println("");


        System.out.println("digit digest from sender(hash value):");
        for (int k=0, j=0; k<HMACmessage.length; k++, j++) {
            System.out.format("%2X ", HMACmessage[k]) ;
            if (j >= 15) {
                System.out.println("\n");
                j=-1;
            }
        }
        System.out.println("");

    }


    public static byte[] ReadAllBytes(String filename) throws IOException {
        File file = new File(filename);
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        return fileBytes;
    }


    private static byte[] SymKey_Decrypt(String PrivKey, String cipheredKey) throws Exception {
        byte[] cipherKey = ReadAllBytes(cipheredKey);
        Key yPrivKey = readPrivKeyFromFile(PrivKey);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, yPrivKey);
        byte[] plainText = cipher.doFinal(cipherKey);
        writeBytes(plainText, "message2.kmk");
        System.out.println("plainText : " + new String(plainText) + "\n");
        for (int k=0, j=0; k < plainText.length; k++, j++) {
            System.out.format("%2X ", plainText[k]) ;
            if (j >= 15) {
                System.out.println("\n");
                j=-1;
            }
        }
        writeBytes(plainText, "decryptedSym.key");
        return plainText;
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


    public static void AES_Decrypt(String AES_message, String SymKey, String outFile)throws Exception{
        byte[] messageCipher = ReadAllBytes(AES_message);
        String IV ="JennyIGot8675309";
        byte[] symKey = ReadAllBytes(SymKey);
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding","SunJCE");
        SecretKeySpec key = new SecretKeySpec(symKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        byte[] finalText = cipher.doFinal(messageCipher);
        appendBytes(finalText, "message2.kmk");
        writeBytes(finalText, outFile);
    }

    public static byte[] calcMessageDigest(String File) throws Exception {
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
        return hash;
    }

    private static String getInput(){
        Scanner input = new Scanner(System.in);
        System.out.println("Input the name of the message file to be saved: ");
        String answer = input.nextLine();
        while (input == null){
            System.out.println("Input the name of the message file to be saved: ");
            answer = input.nextLine();
        }
        return answer;
    }
}
