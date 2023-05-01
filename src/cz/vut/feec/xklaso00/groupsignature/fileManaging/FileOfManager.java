package cz.vut.feec.xklaso00.groupsignature.fileManaging;

import com.herumi.mcl.G2;
import cz.vut.feec.xklaso00.groupsignature.Instructions;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;

public class FileOfManager implements Serializable {

    private BigInteger privateKey;
    private BigInteger managerID;
    private HashMap<BigInteger, byte[]> userHashMap;


    public FileOfManager(BigInteger privateKey, BigInteger managerID) {
        this.privateKey = privateKey;
        this.managerID = managerID;
        userHashMap=new HashMap<>();
    }


    public void addUserToManagerHashMap(BigInteger userID,G2 pubKInverted){
        userHashMap.put(userID,pubKInverted.serialize());

        //save the file in the upper class after this
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getManagerID() {
        return managerID;
    }

    public HashMap<BigInteger, byte[]> getUserHashMap() {
        return userHashMap;
    }
    public void writeOutUsersSaved(){
        userHashMap.forEach((k, v) -> {
            System.out.println("UserID: "+k.toString(16)+" Key inverted: "+ Instructions.bytesToHex(v));
        });
    }
}
