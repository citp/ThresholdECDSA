package thresholdDSA.data;

import java.math.BigInteger;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public class BitcoinParams {
	public static final ECDomainParameters CURVE;
	public static final BigInteger q;
	public static final ECPoint G;

	static {
		X9ECParameters params = SECNamedCurves.getByName("secp256k1");
		CURVE = new ECDomainParameters(params.getCurve(), params.getG(),
				params.getN(), params.getH());
		q = params.getN();
		G = CURVE.getG();
	}
}
