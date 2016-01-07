package thresholdDSA.data;

import java.math.BigInteger;

public class Round3Message {

	public final BigInteger riCommitment;
	public final BigInteger wiCommitment;
	
	public Round3Message(BigInteger riCommitment, BigInteger wiCommitment) {
		this.riCommitment = riCommitment;
		this.wiCommitment = wiCommitment;
	}

}
