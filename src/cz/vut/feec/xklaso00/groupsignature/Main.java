package cz.vut.feec.xklaso00.groupsignature;

import com.herumi.mcl.Mcl;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.NIZKPKFunctions;
import cz.vut.feec.xklaso00.groupsignature.gui.StartWindow;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Main {



    static {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.contains("win")) {
            System.out.println("Running on windows");
            // Windows-specific code
            System.loadLibrary("mcljava-x64");
            //System.loadLibrary("gmp_forJava");
        } else if (osName.contains("nix") || osName.contains("nux") || osName.contains("aix")) {
            // Linux-specific code
            System.out.println("Running on Linux");
            System.loadLibrary("mcljava");
        }
        else{
            System.loadLibrary("mcljava-x64");
        }
    }
    public static void main(String[] args) {


        Mcl.SystemInit(Mcl.BN254);

        /*int bits=4068;
        long st=System.nanoTime();
        BigInteger p=BigInteger.probablePrime(bits/2,new SecureRandom());
        long et=System.nanoTime();
        System.out.println("It took "+(et-st)/1000000+" ms");
        BigInteger q=BigInteger.probablePrime(bits/2,new SecureRandom());
        BigInteger n=p.multiply(q);
        BigInteger g=new BigInteger(bits,new Random());
        BigInteger a=new BigInteger(bits,new Random());
        g=g.mod(n);
        a=a.mod(n);
        st=System.nanoTime();
        g=g.modPow(a,n);
        et=System.nanoTime();
        System.out.println("Mod pow for  "+bits+"took "+(et-st)/1000000+" ms in Java");

        NIZKPKFunctions.setUseGMP(true);
        st=System.nanoTime();
        BigInteger qS= NIZKPKFunctions.myModPow(q,a,n);
        et=System.nanoTime();
        System.out.println("Mod pow for  "+bits+"took "+(et-st)/1000000+" ms in C");*/
        new StartWindow();
    }
}