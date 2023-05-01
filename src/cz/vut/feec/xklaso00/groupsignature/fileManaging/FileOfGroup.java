package cz.vut.feec.xklaso00.groupsignature.fileManaging;

import com.herumi.mcl.G2;

import java.io.Serializable;
import java.math.BigInteger;

public class FileOfGroup implements Serializable {
    private BigInteger managerGroupID;
    private byte[] groupPublicKeyBytes;

    public FileOfGroup(BigInteger managerGroupID, G2 groupPublicKey) {
        this.managerGroupID = managerGroupID;
        this.groupPublicKeyBytes = groupPublicKey.serialize();
    }

    public BigInteger getManagerGroupID() {
        return managerGroupID;
    }

    public G2 getGroupPublicKeyG2() {
        G2 publicKey=new G2();
        publicKey.deserialize(groupPublicKeyBytes);
        return publicKey;
    }
}
