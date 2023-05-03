package cz.vut.feec.xklaso00.groupsignature.fileManaging;

import com.herumi.mcl.G2;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.GothGroup;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.SignatureProof;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;


public class FileManagerClass {
    private static String lastPathOfPDF=null;
    private static byte[][] lastHashSaltAesKey;
    public static byte[] generateSalt ( int length) {
        byte[] salt = new byte[length];
        SecureRandom rand=new SecureRandom();
        rand.nextBytes(salt);
        return salt;
    }
    //hash a password with a salt given, return array, index0:saltedPasswordHash, index1: salt, index2: aesKeyFromPassword
    public static byte[][] hashPassword(char[] pass, byte[] saltBytes)
    {
        PBEKeySpec spec = new PBEKeySpec(pass, saltBytes, 65536, 512);
        try {
            SecretKeyFactory fac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] securePassword = fac.generateSecret(spec).getEncoded();
            byte[][] passAndSalt = new byte[3][];
            passAndSalt[0]=securePassword;
            passAndSalt[1]=saltBytes;
            //we hash the pass without salt to create different hash for AES
            byte[] passwordBytes = new String(pass).getBytes(StandardCharsets.UTF_8);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(passwordBytes);
            /*byte[] aesKeyBytes = Arrays.copyOf(hashedBytes, 32);
            System.out.println("len 1 is "+hashedBytes.length);
            System.out.println("len 2 is "+aesKeyBytes.length);*/
            //System.out.println("len saltedHashIs is "+securePassword.length);
            passAndSalt[2]=hashedBytes;
            return passAndSalt;//we return on index 0 passwordSaltedhash, 1: salt, 2: aesKeyFromPassword

        } catch (Exception e) {
            e.printStackTrace();
            return null;

        } finally {
            spec.clearPassword();
        }
    }
    /*public static boolean savePassword(HashMap<String,byte[][]> passes){
        String path="files/managerHashes.ser";
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(path);
            ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
            out.writeObject(passes);
            out.close();
            fileOutputStream.close();
            System.out.println("manager passes saved to file "+path);
            return true;

        } catch (Exception e) {
            System.out.println("Exception while saving manager passes to file \n"+e.toString());
            return false;
        }
    }
    public static HashMap<String,byte[][]> loadPasses(){
        String path="files/managerHashes.ser";
        try {
            FileInputStream fileIn = new FileInputStream(path);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            HashMap<String,byte[][]> obj=(HashMap<String,byte[][]>)in.readObject();
            in.close();
            fileIn.close();
            System.out.println("manager pass loaded from file "+path);
            return obj;

        } catch (Exception e) {
            System.out.println("Exception while loading manager passes to file \n"+e.toString());
            return null;
        }
    }*/
    public static String saveManagerEncrypted(byte[][] hashSaltAesKey, FileOfManager fileOfManager){
        try {
            StringBuilder sb=new StringBuilder();
            sb.append("files/");
            sb.append(fileOfManager.getManagerID().toString(16));
            sb.append("_keyEnc.ser");
            String fileName=sb.toString();

            ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
            ObjectOutputStream out=new ObjectOutputStream(byteArrayOutputStream);
            out.writeObject(fileOfManager);
            out.close();
            byte[] object=byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();

            SecretKeySpec keySpec = new SecretKeySpec(hashSaltAesKey[2], "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            byte[] ivBytes = new byte[16];
            SecureRandom random=new SecureRandom();
            random.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec,ivSpec);


           byte[] encryptedObj = cipher.doFinal(object);
           byte[][] toFile=new byte[4][];
           toFile[0]=ivBytes; //iv of aes
           toFile[1]=encryptedObj; //encrypted object by aes/
           toFile[2]=hashSaltAesKey[0];//salted hash of the password
           toFile[3]=hashSaltAesKey[1];//salt of the password
           lastHashSaltAesKey=hashSaltAesKey;
           FileOutputStream fos=new FileOutputStream(fileName);
           ObjectOutputStream out2=new ObjectOutputStream(fos);
           out2.writeObject(toFile);
           out2.close();
           fos.close();
           System.out.println("saved to enc file");

            return fileName;
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
    public static int checkPasswordForFile(String filePath, char[] password){
        try {
            lastHashSaltAesKey=null;
            FileInputStream fileIn = new FileInputStream(filePath);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            byte[][] obj = (byte[][]) in.readObject();
            in.close();
            fileIn.close();
            byte[] saltedHash=obj[2];
            byte[] salt=obj[3];
            byte[] []passForCheck=hashPassword(password,salt);
            if(Arrays.equals(saltedHash,passForCheck[0])){
                System.out.println("Password is correct");
                lastHashSaltAesKey=passForCheck;
                return 0;
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return -2;
        }
        return -1;
    }
    public static FileOfManager loadManagerFileEnc(String filePath, byte[] aesKeyBytes){
        try {
            FileInputStream fileIn = new FileInputStream(filePath);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            byte[][] obj=(byte[][])in.readObject();
            in.close();
            fileIn.close();

            byte[] ivBytes=obj[0];
            byte[] encFile=obj[1];
            byte[] saltedHash=obj[2];
            byte[] salt=obj[3];
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));

            // Decrypt encrypted file
            byte[] serializedObject=cipher.doFinal(encFile);
            ByteArrayInputStream bis=new ByteArrayInputStream(serializedObject);
            ObjectInputStream ois=new ObjectInputStream(bis);
            FileOfManager fileOfManager=(FileOfManager) ois.readObject();

            return fileOfManager;

        } catch (Exception e) {
            System.out.println("Exception while loading manager from file \n"+e.toString());
            return null;
        }
    }
    public static String saveManagerKey(FileOfManager FileOfManager){
        StringBuilder sb=new StringBuilder();
        sb.append("files/");
        sb.append(FileOfManager.getManagerID().toString(16));
        sb.append("_key.ser");
        String fileName=sb.toString();

        try {
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
            out.writeObject(FileOfManager);
            out.close();
            fileOutputStream.close();
            System.out.println("manager saved to file "+fileName);
            return fileName;

        } catch (Exception e) {
            System.out.println("Exception while saving manager to file \n"+e.toString());
            return null;
        }
    }
    public static FileOfManager loadManagerFile(String filePath){

        try {
            FileInputStream fileIn = new FileInputStream(filePath);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            FileOfManager obj=(FileOfManager)in.readObject();
            in.close();
            fileIn.close();
            System.out.println("manager loaded from file "+filePath);
            return obj;

        } catch (Exception e) {
            System.out.println("Exception while loading manager from file \n"+e.toString());
            return null;
        }
    }

    public static String saveGroupCertToFile(FileOfGroup fileOfGroup){

        StringBuilder sb=new StringBuilder();
        sb.append("files/");
        sb.append(fileOfGroup.getManagerGroupID().toString(16));
        sb.append("_group_public_key.ser");
        String fileName=sb.toString();
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
            out.writeObject(fileOfGroup);
            out.close();
            fileOutputStream.close();
            System.out.println("Group public key saved to file "+fileName);
            return fileName;

        } catch (Exception e) {
            System.out.println("Exception while saving group public key file ");
            e.printStackTrace();

            return null;
        }
    }
    public static G2 loadPublicKeyForGroup(BigInteger groupID){
        String groupIDString=groupID.toString(16);
        StringBuilder sb=new StringBuilder();
        sb.append("files/");
        sb.append(groupIDString);
        sb.append("_group_public_key.ser");
        String fileName=sb.toString();
        try {
            FileInputStream fileIn = new FileInputStream(fileName);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            FileOfGroup obj=(FileOfGroup)in.readObject();
            return obj.getGroupPublicKeyG2();
        }
        catch (Exception e){
            e.printStackTrace();
        }
        String secondaryPath=chooseFile("Choose the group_public_key file manually");
        try {
            FileInputStream fileIn = new FileInputStream(secondaryPath);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            FileOfGroup obj=(FileOfGroup)in.readObject();
            return obj.getGroupPublicKeyG2();
        }
        catch (Exception e){
            e.printStackTrace();
        }


        return null;
    }
    public static String chooseFile(String messageToShow){
        File file;
        JFileChooser fileChooser =new JFileChooser();
        fileChooser.setCurrentDirectory((new File(".")));
        fileChooser.setDialogTitle(messageToShow);
        int res=fileChooser.showOpenDialog(null);
        if(res==JFileChooser.APPROVE_OPTION){
            file=fileChooser.getSelectedFile();
            String path=file.getAbsolutePath();
            file=null;
            fileChooser=null;
            return path;
        }
        else
            return null;
    }
    public static byte[] ChooseAndHashFile(BigInteger nOfCurve){
        String fileName=chooseFile("Choose a .pdf file");
        //Path filePath= Paths.get(fileName);
        lastPathOfPDF=fileName;
        //System.out.println("filename "+fileName);
        try {
            //byte[] pdf = Files.readAllBytes(filePath);
            byte [] pdf=PDFManager.getContentBytesOfPDF(fileName);
            return hashFileBytes(pdf,nOfCurve);

        } catch (Exception e) {
            System.out.println("Error while reading and hashing the file");
            e.printStackTrace();
            return null;
        }
    }


    public static byte[] hashFileBytes(byte[] fileBytes,BigInteger nOfCurve){
        MessageDigest hashing;
        try {
            hashing= MessageDigest.getInstance("SHA-256");
            hashing.update(fileBytes);
            byte[] hash=hashing.digest();
            BigInteger hashBig=new BigInteger(hash);
            hashBig=hashBig.mod(nOfCurve);
            hash=hashBig.toByteArray();
            return hash;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static void saveSignature(SignatureProof signatureProof){
        /*String pathString=lastPathOfPDF;
        //System.out.println("Path is "+pathString);
        pathString=pathString.split("\\.")[0];
        //System.out.println("Split is "+pathString);
        StringBuilder sb=new StringBuilder();
        sb.append(pathString);
        sb.append("_signature.ser");
        pathString=sb.toString();
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(pathString);
            ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
            out.writeObject(signatureProof);
            out.close();
            fileOutputStream.close();
            System.out.println("Signature saved to file "+pathString);

        } catch (Exception e) {
            e.printStackTrace();
        }*/
        byte[] sigProofBytes;

        try {
            ByteArrayOutputStream outputStream=new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(outputStream);
            out.writeObject(signatureProof);
            out.flush();
            sigProofBytes=outputStream.toByteArray();
            outputStream.close();
            out.close();

            String newFile=PDFManager.saveSignatureToMetadata(lastPathOfPDF,sigProofBytes);
            System.out.println("SIG SAVED to "+newFile);
            //System.out.println("sp "+signatureProof.groupID);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    public static SignatureProof loadSignature(String pdfPath){
        /*String newPath=pdfPath.split("\\.")[0];
        StringBuilder sb=new StringBuilder();
        sb.append(newPath);
        sb.append("_signature.ser");
        newPath=sb.toString();
        try {
            FileInputStream fis=new FileInputStream(newPath);
            ObjectInputStream ois=new ObjectInputStream(fis);
            SignatureProof signatureProof= (SignatureProof) ois.readObject();
            return signatureProof;


        } catch (Exception e) {
            e.printStackTrace();
            return  null;
        }*/
        byte[] sigBytes=PDFManager.readSigFromMetadata(pdfPath);
        ByteArrayInputStream inputStream=new ByteArrayInputStream(sigBytes);
        try {
            ObjectInputStream objectInputStream=new ObjectInputStream(inputStream);
            SignatureProof signatureProof= (SignatureProof) objectInputStream.readObject();
            //System.out.println("sp "+signatureProof.groupID);

            return signatureProof;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static int saveRevokedToFile(BigInteger groupID, HashSet<byte[]> revokedUsers){
        StringBuilder sb=new StringBuilder();
        sb.append("files/");
        sb.append(groupID.toString(16));
        sb.append("_revoked_users.ser");
        String pathToSave=sb.toString();

        try {
            FileOutputStream fos=new FileOutputStream(pathToSave);
            ObjectOutputStream oos=new ObjectOutputStream(fos);
            oos.writeObject(revokedUsers);
            oos.close();
            fos.close();
            System.out.println("REVOKED SAVED TO "+pathToSave );
            return 0;

        } catch (Exception e) {
            e.printStackTrace();
            return -2;
        }
    }
    public static HashSet<byte[]> loadRevokedUsers(BigInteger groupID){
        StringBuilder sb=new StringBuilder();
        sb.append("files/");
        sb.append(groupID.toString(16));
        sb.append("_revoked_users.ser");
        String pathToLoad=sb.toString();
        try {
            FileInputStream fis=new FileInputStream(pathToLoad);
            ObjectInputStream ois=new ObjectInputStream(fis);
            HashSet<byte[]> revokedUsers= (HashSet<byte[]>) ois.readObject();
            System.out.println("REVOKED loaded  "+pathToLoad );
            return revokedUsers;
        } catch (Exception e) {
            e.printStackTrace();
        }

        //if I cannot find the file lets try it manually
        String secPath=chooseFile("cannot find revocation list, give it to me manually");
        try {
            FileInputStream fis=new FileInputStream(secPath);
            ObjectInputStream ois=new ObjectInputStream(fis);
            HashSet<byte[]> revokedUsers= (HashSet<byte[]>) ois.readObject();
            return revokedUsers;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
    
    public static int generateAndSaveGothToFile(int bitsize){
        GothGroup gothGroup=new GothGroup(bitsize);
        String fileName="files/gothicParameters/gothGroup.ser";
        try {
            FileOutputStream fos=new FileOutputStream(fileName);
            ObjectOutputStream oos=new ObjectOutputStream(fos);
            oos.writeObject(gothGroup);
            oos.close();
            fos.close();
            System.out.println("GOTH SAVED TO "+fileName );
            return 0;

        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    public static GothGroup loadGothParameters(){
        String fileName="files/gothicParameters/gothGroup.ser";
        try {
            FileInputStream fis=new FileInputStream(fileName);
            ObjectInputStream ois=new ObjectInputStream(fis);
            GothGroup gothGroup= (GothGroup) ois.readObject();
            System.out.println("goth loaded  "+fileName );
            return gothGroup;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static boolean tryFiles(){
            File dir=new File("files");
            if(!dir.exists()){
                boolean b=dir.mkdirs();
                if(!b) {
                    System.out.println("Could not create or find files");
                    return false;
                }
                System.out.println("could not find files, but created it");
            }
            return true;
    }
    public static String getLastPathOfPDF() {
        return lastPathOfPDF;
    }

    public static byte[][] getLastHashSaltAesKey() {
        return lastHashSaltAesKey;
    }
}
