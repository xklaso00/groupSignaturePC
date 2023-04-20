package cz.vut.feec.xklaso00.semestralproject;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class PaillierKeyPair {

    private PaillierPrivateKey paillierPrivateKey;
    private PaillierPublicKey paillierPublicKey;
    private BigInteger q;
    private BigInteger p;
    private BigInteger Mu;

    private String TAG= "TimeStampsPaillier";
    public PaillierKeyPair(int bitSize){
        Random rng= new SecureRandom();
        long st= System.nanoTime();
        p= PaillierFunctions.generateRandomPrime(bitSize/2);
        q=PaillierFunctions.generateRandomPrime(bitSize/2);
        long et= System.nanoTime();

        BigInteger n= p.multiply(q);
        BigInteger nn= n.pow(2);

        BigInteger lambda= this.lcm(p.subtract(BigInteger.ONE),q.subtract(BigInteger.ONE));
        //System.out.println("lambda: "+lambda);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        //System.out.println("phi: "+phi);
        //BigInteger g =generateG(bitSize,n,lambda,nn);
        BigInteger g =generateG(bitSize,n,phi,nn);


        //Goth
        BigInteger pGoth=PaillierFunctions.generateRandomPrime(bitSize/2);
        BigInteger qGoth=PaillierFunctions.generateRandomPrime(bitSize/2);
        BigInteger nGoth=pGoth.multiply(qGoth);

        pGoth=pGoth.subtract(new BigInteger("1"));
        qGoth=qGoth.subtract(new BigInteger("1"));
        BigInteger phiNGoth=pGoth.multiply(qGoth);

        BigInteger hGoth=PaillierFunctions.getRandom(bitSize,nGoth);
        BigInteger randGoth=PaillierFunctions.getRandom(phiNGoth.bitLength(),phiNGoth);
        BigInteger gGoth=hGoth.modPow(randGoth,nGoth);



        //paillierPublicKey= new cz.vut.feec.xklaso00.semestralproject.PaillierPublicKey(n,g,nn,bitSize);
        paillierPublicKey= new PaillierPublicKey(n,g,nn,bitSize,nGoth,hGoth,gGoth);
        //paillierPrivateKey= new cz.vut.feec.xklaso00.semestralproject.PaillierPrivateKey(lambda,Mu,n,nn,phi);
        //paillierPrivateKey= new PaillierPrivateKey(lambda,Mu,n,nn,phi,phiNGoth);
        paillierPrivateKey= new PaillierPrivateKey(lambda,Mu,n,nn,phi);
    }
    public PaillierKeyPair(int bitSize,GothGroup gothGroup){
        p= PaillierFunctions.generateRandomPrime(bitSize/2);
        q=PaillierFunctions.generateRandomPrime(bitSize/2);
        BigInteger n= p.multiply(q);
        BigInteger nn= n.pow(2);
        //System.out.println("nn len is "+nn.bitLength());
        BigInteger lambda= this.lcm(p.subtract(BigInteger.ONE),q.subtract(BigInteger.ONE));

        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger g =generateG(bitSize,n,phi,nn);
        paillierPublicKey= new PaillierPublicKey(n,g,nn,bitSize,gothGroup.getnGoth(),gothGroup.gethGoth(),gothGroup.getgGoth());
        paillierPrivateKey= new PaillierPrivateKey(lambda,Mu,n,nn,phi);
    }
    private BigInteger lcm(BigInteger a, BigInteger b){
        if (a.signum() == 0 || b.signum() == 0)
            return BigInteger.ZERO;
        return a.divide(a.gcd(b)).multiply(b).abs();
    }
    private  BigInteger generateG(int bitSize, BigInteger n, BigInteger lambda, BigInteger nn){
        BigInteger generator;
        BigInteger comp;
        Random rng= new SecureRandom();
        long st= System.nanoTime();
        do{
            generator= new BigInteger(bitSize,rng);
            /*BigInteger insideL= generator.modPow(lambda,nn);

            comp=insideL.subtract(BigInteger.ONE);
            comp= comp.divide(n);*/

            //generator=generator.modPow(n,nn);
            //comp=generator.modPow(lambda,nn);
            generator=PaillierFunctions.myModPow(generator,n,nn);
            comp=PaillierFunctions.myModPow(generator,lambda,nn);
        }while (!comp.gcd(n).equals(BigInteger.ONE));
        long et= System.nanoTime();

        st= System.nanoTime();
        this.Mu=comp.modInverse(n);
        et= System.nanoTime();

        return generator;
    }

    public PaillierPrivateKey getPaillierPrivateKey() {
        return paillierPrivateKey;
    }
    public native String prime(String beforeNumber);
    public PaillierPublicKey getPaillierPublicKey() {
        return paillierPublicKey;
    }
}
