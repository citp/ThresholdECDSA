package Common.Commitments;

import java.math.BigInteger;

import uk.ac.ic.doc.jpair.pairing.Point;

public class Commitment {
	
	public final BigInteger pubkey;
	public final Point committment;
	
	public Commitment(BigInteger pubkey, Point a) {
		this.pubkey = pubkey;
		this.committment = a;
		
	}

}
