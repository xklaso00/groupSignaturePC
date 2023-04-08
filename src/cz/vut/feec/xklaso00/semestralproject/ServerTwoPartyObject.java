package cz.vut.feec.xklaso00.semestralproject;

import java.io.Serializable;
import java.math.BigInteger;

public class ServerTwoPartyObject implements Serializable {
    private PaillierPublicKey paillierPublicKey;
    private BigInteger e1;
    private BigInteger[] ZKs;
    private BigInteger cGoth;
    private BigInteger eHash;



    public ServerTwoPartyObject(PaillierPublicKey paillierPublicKey, BigInteger e1, BigInteger[] ZKs, BigInteger cGoth, BigInteger eHash) {
        this.paillierPublicKey = paillierPublicKey;
        this.e1 = e1;
        this.ZKs = ZKs;
        this.cGoth = cGoth;
        this.eHash = eHash;
    }

    public PaillierPublicKey getPaillierPublicKey() {
        return paillierPublicKey;
    }

    public BigInteger getE1() {
        return e1;
    }

    public BigInteger[] getZKs() {
        return ZKs;
    }

    public BigInteger getcGoth() {
        return cGoth;
    }

    public BigInteger geteHash() {
        return eHash;
    }
}
