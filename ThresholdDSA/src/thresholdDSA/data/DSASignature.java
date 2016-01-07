package thresholdDSA.data;

import java.math.BigInteger;

public class DSASignature {
	public final BigInteger r;
	public final BigInteger s;
	
	public DSASignature(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;
	}

}
