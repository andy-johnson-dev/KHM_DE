

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;



import static jdk.nashorn.internal.runtime.ScriptingFunctions.readLine;

public class RSA_keygen {
    public static void main(String[] args) throws Exception {


        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");


        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);  //1024: key size in bits
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();


        //get the parameters of the keys: modulus and exponent
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey, RSAPrivateKeySpec.class);

        //save the parameters of the keys to the files
        saveToFile("YPublic.key", pubKSpec.getModulus(), pubKSpec.getPublicExponent());
        saveToFile("YPrivate.key", privKSpec.getModulus(), privKSpec.getPrivateExponent());
        saveToFile("XPublic.key", pubKSpec.getModulus(), pubKSpec.getPublicExponent());
        saveToFile("XPrivate.key", privKSpec.getModulus(), privKSpec.getPrivateExponent());

        //read the keys back from the files
        PublicKey pubKey2 = readPubKeyFromFile("YPublic.key");
        PrivateKey privKey2 = readPrivKeyFromFile("YPrivate.key");
        generateSymKey();
        System.out.println(pubKey2);

    }

   //save the prameters of the public and private keys to file
    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {

//        System.out.println("Write to " + fileName + ": modulus = " + mod.toString() + ",\n  \t\t\t\t\texponent = " + exp.toString() + "\n");
        ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }


    //read key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {
        InputStream in = RSA_keygen.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
//            System.out.println("Read from " + keyFileName + ": modulus = " + m.toString() + ", \n \t\t\t\t\texponent = " + e.toString() + "\n");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }


    //read key parameters from a file and generate the private key
    public static PrivateKey readPrivKeyFromFile(String keyFileName)
            throws IOException {

        InputStream in = RSA_keygen.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
//            System.out.println("Read from " + keyFileName + ": modulus = " + m.toString() + ", \n\t\t\t\t\texponent = " + e.toString() + "\n");
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }



    public static void generateSymKey(){
        Scanner userInput = new Scanner(System.in);
        System.out.println("Please enter 16 character string for a symmetric key.");
        String symKey = userInput.nextLine();
        while (symKey == null || symKey.length() != 16) {
            System.out.println("Incorrect input!");
            System.out.println("Please enter 16 character string for a symmetric key.");
            symKey = userInput.nextLine();
        }
        System.out.println("Symmetric Key : " + symKey);
        byte[] symKeyFinal = symKey.getBytes(StandardCharsets.UTF_8);
        System.out.println(symKeyFinal);

        try {
            OutputStream os = new FileOutputStream("symmetric.key");
            os.write(symKeyFinal);
            os.close();
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
    }
}
