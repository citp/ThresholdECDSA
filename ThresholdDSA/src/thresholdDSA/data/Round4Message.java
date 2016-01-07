package thresholdDSA.data;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import PedersenCommitments.Open;
import ZeroKnowledgeProofs.Zkp_i2;

public class Round4Message {
	
	public final Open<ECPoint> openRi;
	public final Open<BigInteger> openWi;
	public final Zkp_i2 zkp2;

	public Round4Message(Open<ECPoint> openRi, Open<BigInteger> openWi, Zkp_i2 zkp2) {
		this.openRi = openRi;
		this.openWi = openWi;
		this.zkp2 = zkp2;
	}
}
