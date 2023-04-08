package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.G2;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;

public class managerFile implements Serializable {

    private BigInteger privateKey;
    private BigInteger managerID;
    private HashMap<BigInteger, G2> userHashMap;

    public managerFile(BigInteger privateKey, BigInteger managerID) {
        this.privateKey = privateKey;
        this.managerID = managerID;
        userHashMap=new HashMap<>();
    }


    public void addUserToManagerHashMap(BigInteger userID,G2 pubKInverted){
        userHashMap.put(userID,pubKInverted);
        //save to file here probably
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getManagerID() {
        return managerID;
    }

    public HashMap<BigInteger, G2> getUserHashMap() {
        return userHashMap;
    }
}
