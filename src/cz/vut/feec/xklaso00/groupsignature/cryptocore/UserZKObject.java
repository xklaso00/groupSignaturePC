package cz.vut.feec.xklaso00.groupsignature.cryptocore;

import com.herumi.mcl.G2;

import java.io.Serializable;
import java.math.BigInteger;

public class UserZKObject implements Serializable {
    private BigInteger[] Zets;
    private BigInteger e2;
    private BigInteger c2Goth;
    private  BigInteger eClientHash;
    private byte[] clientPubKey;
    private BigInteger clientID;

    public UserZKObject(BigInteger[] zets, BigInteger e2, BigInteger c2Goth, BigInteger eClientHash, byte[] clientPubKey,BigInteger clientID) {
        Zets = zets;
        this.e2 = e2;
        this.c2Goth = c2Goth;
        this.eClientHash = eClientHash;
        this.clientPubKey = clientPubKey;
        this.clientID=clientID;
    }

    public BigInteger getClientID() {
        return clientID;
    }

    public BigInteger[] getZets() {
        return Zets;
    }

    public BigInteger getE2() {
        return e2;
    }

    public BigInteger getC2Goth() {
        return c2Goth;
    }

    public BigInteger geteClientHash() {
        return eClientHash;
    }

    public G2 getClientPubKey() {

        G2 pub=new G2();
        pub.deserialize(clientPubKey);
        return pub;
    }
}
