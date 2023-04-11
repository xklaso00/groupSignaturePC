package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.G2;

import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;

public class FileManagerClass {


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
    public static byte[] hashFile(BigInteger nOfCurve){
        String fileName=chooseFile("Choose a .pdf file to sign");
        Path filePath= Paths.get(fileName);
        try {
            byte[] pdf = Files.readAllBytes(filePath);
            MessageDigest hashing;
            hashing= MessageDigest.getInstance("SHA-256");
            hashing.update(pdf);
            byte[] hash=hashing.digest();
            BigInteger hashBig=new BigInteger(hash);
            hashBig=hashBig.mod(nOfCurve);
            hash=hashBig.toByteArray();
            return hash;



        } catch (Exception e) {
            System.out.println("Error while reading and hashing the file");
            e.printStackTrace();
            return null;
        }
    }
}
