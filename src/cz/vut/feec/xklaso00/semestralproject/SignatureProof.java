package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;

import java.io.Serializable;

public class SignatureProof implements Serializable {

    public G1 gToR;
    public G1 SiAph;
    public G1 SiDash;
    public Fr E;
    public Fr Sr;
    public Fr SSki;

    public SignatureProof(G1 gToR, G1 siAph, G1 siDash, Fr e, Fr sr, Fr SSki) {
        this.gToR = gToR;
        SiAph = siAph;
        SiDash = siDash;
        E = e;
        Sr = sr;
        this.SSki = SSki;
    }
}
