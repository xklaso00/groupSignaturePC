package cz.vut.feec.xklaso00.semestralproject;

import java.math.BigInteger;

public class PaillierPrivateKey {


    private BigInteger lambda;
    private BigInteger Mu;
    private BigInteger n;
    private BigInteger nn;
    private BigInteger phi;
    //private BigInteger phiNGoth;
    public PaillierPrivateKey(BigInteger lambda, BigInteger Mu,BigInteger n,BigInteger nn, BigInteger phi){
        this.lambda=lambda;
        this.Mu=Mu;
        this.n=n;
        this.nn=nn;
        this.phi=phi;
    }
   /* public PaillierPrivateKey(BigInteger lambda, BigInteger Mu,BigInteger n,BigInteger nn, BigInteger phi, BigInteger phiNGoth){
        this.lambda=lambda;
        this.Mu=Mu;
        this.n=n;
        this.nn=nn;
        this.phi=phi;
        this.phiNGoth=phiNGoth;
    }*/


    public BigInteger getLambda() {
        return lambda;
    }

    public BigInteger getMu() {
        return Mu;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getNn() {
        return nn;
    }

    public BigInteger getPhi() {
        return phi;
    }


}
