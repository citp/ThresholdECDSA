package Common.Commitments;

public class Open<T> {
	
	private final T[] secrets;
	private final T randomness;
	
	public Open(T randomness, T... secrets) {
		this.secrets = secrets;
		this.randomness = randomness;
	}

	public T[] getSecrets() {
		return secrets;
	}
	
	public T getRandomness() {
		return randomness;
	}

}
