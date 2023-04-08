package cz.vut.feec.xklaso00.semestralproject;

import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;

public class PaillierPublicKey implements Serializable {
    private BigInteger n;
    private BigInteger g;
    private BigInteger nn;
    private int bitSize;
    private BigInteger nGoth;
    private BigInteger hGoth;
    private BigInteger gGoth;
    private BigInteger nHalf;

    public PaillierPublicKey(BigInteger n, BigInteger g, BigInteger nn, int bitSize){
        this.g=g;
        this.n=n;
        this.nn=nn;
        this.bitSize=bitSize;
    }
    public PaillierPublicKey(BigInteger n, BigInteger g, BigInteger nn, int bitSize, BigInteger nGoth,BigInteger hGoth,BigInteger gGoth){
        this.g=g;
        this.n=n;
        this.nn=nn;
        this.bitSize=bitSize;
        this.nGoth=nGoth;
        this.hGoth=hGoth;
        this.gGoth=gGoth;

        BigDecimal bd= new BigDecimal(n);
        bd= bd.divide(new BigDecimal(2), RoundingMode.FLOOR);

        nHalf= bd.toBigInteger();
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getNn() {
        return nn;
    }

    public int getBitSize() {
        return bitSize;
    }
    public BigInteger getH(){
        return  n.add(BigInteger.ONE);
    }

    public BigInteger getNGoth() {
        return nGoth;
    }

    public BigInteger getHGoth() {
        return hGoth;
    }

    public BigInteger getGGoth() {
        return gGoth;
    }

    public BigInteger getnHalf() {
        return nHalf;
    }
}
