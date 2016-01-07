package thresholdDSA.data;

import java.math.BigInteger;

public class Round1Message {
	public final BigInteger uiCommitment;
	public final BigInteger vICommitment;

	public Round1Message(BigInteger uiCommitment, BigInteger vICommitment) {
		this.uiCommitment = uiCommitment;
		this.vICommitment = vICommitment;
	}

}
