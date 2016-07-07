package Common.Commitments;

import java.math.BigInteger;

import uk.ac.ic.doc.jpair.api.Pairing;
import uk.ac.ic.doc.jpair.pairing.Point;


public class MultiTrapdoorMasterPublicKey {

	/** Master public key for NM commitment scheme of Gennaro*/
	public final Point g;
	public final BigInteger q; //AR include order in MPK
	public final Point h;
	public final Pairing pairing; //AR include ok
	
	public MultiTrapdoorMasterPublicKey(Point g, BigInteger q, Point h, uk.ac.ic.doc.jpair.api.Pairing pairing) {
		this.g = g;
		this.h = h;
		this.q = q;
		this.pairing = pairing;
	}


}
