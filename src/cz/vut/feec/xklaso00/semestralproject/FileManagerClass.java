package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.G2;

import java.io.*;
import java.math.BigInteger;

public class FileManagerClass {


    public void saveManagerKey(managerFile managerFile){
        StringBuilder sb=new StringBuilder();
        sb.append(managerFile.getManagerID().toString(16));
        sb.append("_key.ser");
        String fileName=sb.toString();

        try {
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
            out.writeObject(managerFile);
            out.close();
            fileOutputStream.close();

        } catch (Exception e) {
            System.out.println("Exception while saving manager to file \n"+e.toString());
        }

    }
    public managerFile loadManagerFile(String fileName){

        try {
            FileInputStream fileIn = new FileInputStream(fileName);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            managerFile obj=(managerFile)in.readObject();
            in.close();
            fileIn.close();
            return obj;

        } catch (Exception e) {
            System.out.println("Exception while loading manager from file \n"+e.toString());
            return null;
        }
    }

    public void saveGroupCertToFile(String groupID, G2 groupPublicKey){

    }
}
