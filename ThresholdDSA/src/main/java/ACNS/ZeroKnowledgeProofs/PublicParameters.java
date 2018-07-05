package ACNS.ZeroKnowledgeProofs;

import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import paillierp.key.PaillierKey;

public class PublicParameters implements Serializable {

	private static final long serialVersionUID = 446196880585148373L;
	public final byte[] gRaw;
	public final BigInteger h1;
	public final BigInteger h2;
	public final BigInteger nTilde;
	public final PaillierKey paillierPubKey;

	public PublicParameters(ECDomainParameters CURVE, BigInteger nTilde, BigInteger h1, BigInteger h2,
			PaillierKey paillierPubKey) {
		gRaw = CURVE.getG().getEncoded();
		this.nTilde = nTilde;
		this.h1 = h1;
		this.h2 = h2;
		this.paillierPubKey = paillierPubKey;
	}

	public ECPoint getG(ECDomainParameters curve) {
		return curve.getCurve().decodePoint(gRaw);
	}
}
