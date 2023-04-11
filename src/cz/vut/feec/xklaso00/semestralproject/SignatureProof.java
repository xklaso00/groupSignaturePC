package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;


import java.io.Serializable;
import java.math.BigInteger;

public class SignatureProof implements Serializable {

    /*public G1 gToR;
    public G1 SiAph;
    public G1 SiDash;*/
    private byte[]gToRBytes;
    private byte[]SiAphBytes;
    private byte[]SiDashBytes;

    //public Fr E;
    private byte [] eBytes;
    //public Fr Sr;
    private byte [] SrBytes;
    //public Fr SSki;
    private byte [] SSKiBytes;
    public BigInteger groupID;

    public SignatureProof(G1 gToR, G1 siAph, G1 siDash, Fr e, Fr sr, Fr SSki,BigInteger groupID) {
        gToRBytes=gToR.serialize();
        SiAphBytes=siAph.serialize();
        SiDashBytes=siDash.serialize();
        eBytes=e.serialize();
        SrBytes=sr.serialize();
        SSKiBytes=SSki.serialize();

        this.groupID=groupID;
    }
    public Fr getE(){
        Fr toRet=new Fr();
        toRet.deserialize(eBytes);
        return toRet;
    }
    public Fr getSr(){
        Fr toRet=new Fr();
        toRet.deserialize(SrBytes);
        return toRet;
    }
    public Fr getSSki(){
        Fr toRet=new Fr();
        toRet.deserialize(SSKiBytes);
        return toRet;
    }
    public G1 getGToR(){
        G1 toRet=new G1();
        toRet.deserialize(gToRBytes);
        return toRet;
    }
    public G1 getSiAph(){
        G1 toRet=new G1();
        toRet.deserialize(SiAphBytes);
        return toRet;
    }
    public G1 getSiDash(){
        G1 toRet=new G1();
        toRet.deserialize(SiDashBytes);
        return toRet;
    }
}
