package ACNS.thresholdDSA.data;

import java.math.BigInteger;

import ACNS.ZeroKnowledgeProofs.Zkp_i2;
import Common.Commitments.Open;

public class Round4Message {
	
	public final Open<BigInteger> openRiWi;
	public final Zkp_i2 zkp2;

	public Round4Message(Open<BigInteger> openRiWi, Zkp_i2 zkp2) {
		this.openRiWi = openRiWi;
		this.zkp2 = zkp2;
	}
}
