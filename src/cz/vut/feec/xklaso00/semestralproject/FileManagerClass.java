package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.G2;

import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;

public class FileManagerClass {
    private static String lastPathOfPDF=null;

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
            return file.getAbsolutePath();
        }
        else
            return null;
    }
    public static byte[] ChooseAndHashFile(BigInteger nOfCurve){
        String fileName=chooseFile("Choose a .pdf file");
        Path filePath= Paths.get(fileName);
        lastPathOfPDF=fileName;
        System.out.println("filename "+fileName);
        try {
            byte[] pdf = Files.readAllBytes(filePath);
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
        String pathString=lastPathOfPDF;
        System.out.println("Path is "+pathString);
        pathString=pathString.split("\\.")[0];
        System.out.println("Split is "+pathString);
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
        }
    }
    public static SignatureProof loadSignature(String pdfPath){
        String newPath=pdfPath.split("\\.")[0];
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
        }
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
    public static String getLastPathOfPDF() {
        return lastPathOfPDF;
    }
}
