package thresholdDSA.data;

import paillierp.PartialDecryption;

public class Round5Message {
	
	public final PartialDecryption wShare;

	public Round5Message(PartialDecryption wShare) {
		this.wShare = wShare;
	}

}
