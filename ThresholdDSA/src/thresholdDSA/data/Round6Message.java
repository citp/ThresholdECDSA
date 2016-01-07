package thresholdDSA.data;

import paillierp.PartialDecryption;

public class Round6Message {

	public final PartialDecryption sigmaShare;

	public Round6Message(PartialDecryption sigmaShare) {
		this.sigmaShare = sigmaShare;
	}

}
