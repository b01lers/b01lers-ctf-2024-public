# Writeup for schnore by enigcryptist

## Details
- **Type**: crypto
- **Difficulty**: Easy
- **Flag format**: `bctf{...}`

## Run Instructions

```bash
# Build Docker image
./run.sh
# Run chal in a Docker container
docker run -it deploy_schnore
# In a new terminal...
nc localhost 5093
```

## Solution

### Summary (TL;DR)
The provided code involves a verifier challenging a potentially malicious prover (you!) to demonstrate that they know some private value $x$ that corresponds to a public agreed-upon value $X := g^x \bmod p$, without revealing any information about $x$ (i.e., a zero-knowledge proof or ZKP). It uses a weak Fiat-Shamir (FS) transformation to transform an interactive ZKP into non-interactive by including *only some* public values as input to the hash as a challenge. Since $X$ is not included in the verifier's challenge and the malicious prover can adaptively convince the verifier to use any public value $X$, a malicious prover can work backward from the verification equation to forge a non-sound proof that they know the "discrete-log" value $x$ in $X$, when in reality they do not. If all public values were included as the hash input to generate the challenge (including $X$, i.e. strong Fiat-Shamir), or the prover and verifier were forced to agree on a value $X$ out-of-band before constructing the proof, this attack would not have been possible because they would be bound to use a specific public value $X$ before constructing their proof.

### Background: Schnorr Signatures and Fiat-Shamir ZKPs
First, the public parameters are decided as primes $p,q$ and an element ("generator") $g$ which produces an order $q$ multiplicative subgroup $\mathbb{G} := \langle g \rangle$ in the integers modulo $p$ (i.e. $\mathbb{Z}_p$). An honest signer decides on a private signing key $x$ and their corresponding public verification key $X = g^x \mod p \in \mathbb{G}$. An interactive proof construction roughly follows what's called a "Sigma protocol", named as such due to the shape of the protocol interaction resembling the Greek letter Sigma, $\Sigma$ [^1]:
1. (&ndash;) The Prover and Verifier first agree on any relevant **public information** shared between the Prover and Verifier (here, $p,q,g$). <details><summary>Spoiler (and security) alert!!!</summary>(For security reasons, $X$ should also be included here; see below)</details>
2. (\\) The Prover then generates a random value (here, $a \gets \mathbb{Z}_p^*$) and sends its corresponding **commitment** to the Verifier (here, $A = g^a \bmod p \in \mathbb{G}$).
3. (/) The Verifier responds back with a **challenge** value (here, $c \in \mathbb{Z}_p^*$), attempting to verify the Prover's knowledge of some **private information**, aka **witness** (here, $x$) corresponding with the public key (here, $X := g^x \mod p \in \mathbb{G}$). 
4. (&ndash;) The Prover computes the final **proof** based on both the commitment and the challenge (here, $z = a + c * x \mod p \in \mathbb{Z}_p^*$, which is checked by the Verifier using the corresponding public keys and other information.

At a high level, the Fiat-Shamir (FS) heuristic provides a mechanism for transforming *interactive* Sigma proofs such as these into *non-interactive* Sigma proofs by instead having the Prover hash these public values and commitments as its challenge instead of having it sent by the Verifier. As long as the hash output is cryptographically "random-looking" (more formally, that the hash function $H$ can be assumed to be a random oracle which cannot be inverted or guessed prior to querying its output), this works effectively the same way an interactive challenge would. FS can be classified into two types:
1. **Weak Fiat-Shamir**, where only the necessary committed values are hashed into a challenge, and
2. **Strong Fiat-Shamir**, where it is hashed together with ALL other public information that is used by the protocol and known to both the Prover and Verifier in advance (group generator(s), group description / parameters, public key(s), etc.).

### Background: Challenge

This challenge involves a cryptographic proof over a Schnorr signatures, which is based on the discrete log hardness assumption. In a normal but weak FS Schnorr protocol, an honest Prover would generate $a \gets \mathbb{Z}_p$ randomly and compute $A = g^a \mod p$ as its commitment, with $c = H(g,p,A)$ as its challenge. As its proof of knowledge on $x$, it computes $z = a + c * x \mod p$ before sending $(A,z)$ to the Verifier. The Verifier then checks this was correctly computed by computing $c = H(g,p,A)$ themselves and checking the following:
$$g^z \stackrel{?}{=} A * X^c \mod p$$

As we shall soon see, not expecting enough information in the hash as a challenge makes it easy for the prover to lie to the Verifier about knowledge of the secret signing key $x$ in the non-interactive setting.

### Vulnerability: Weak Fiat-Shamir

In many situations, where the public key is decided ahead of time by the prover and verifier, this is sufficient to ensure that even a malicious prover must know $x$ corresponding with $X = g^x$, and is bound to the public information chosen to be included in the hash. *However*, if the malicious prover is adaptive and has the ability to control which public key $X$ is used by the verifier (i.e., is not bound to to commit to $X = g^x$ *before* computing and sending over $z = a + c * x$), this is insufficient to stop the prover from lying about knowing $x$.

Instead, consider a malicious prover who does not know $x$. Since they can't compute discrete log of $X = g^x \bmod p$ to get $x$ either due to well-studied cryptographic assumptions, they're forced to choose $z \gets \mathbb{F}_p^*$ randomly instead of computing it. Choose $A \gets \mathbb{G}$ randomly as well, then compute $c = H(g,p,A)$ as the verifier would. To ensure that the verification check passes, the malicious prover simply re-arranges the verification equation to solve for $X$, and has the verifier agree to use this public key $X$:
$$X = (A^{-1} * g^z)^{(c^{-1} \mod p-1)} \mod p$$

And so, as long as the attacker can convince the verifier to use a maliciously chosen verification key $X$ *after* having generated $A$ and $z$, and that this value $X$ is not included within the challenge itself (i.e. as in strong FS), they have successfully forged a satisfying proof of knowledge on $x$ to the Verifier while only having known $X$. The attack involves following these steps above to obtain the flag.

The only caveat is that $c = H(g,p,A)$ might not always be invertible in the exponent (i.e. modulo $\phi(p) = p - 1$) since $p-1$ is even and might share a common factor (here, we made it simple for you by ensuring $gcd(c, p-1) = 2)$. With this specific challenge value $c$, you might have to do a bit more algebra to recover $X$ by finding a "partial inversion" $c^{-1'}$ for which $c * c^{-1'} = 2 \bmod p \equiv (c/2) * c^{-1'} = 1 \bmod (p/2)$, using this to compute $X^2 \mod p$, then finding $X$ via a quadratic residue ("modular square root") algorithm such as Tonelli-Shanks. Hint hint, this is a relatively easy-level trick used to recover messages from poorly chosen RSA keys ;)

See [`src/solve.py`](src/solve.py) and below for more details, courtesy [^2][^3]:

![A comparison between "Interactive Schnorr protocol", "Strong/Weak Fiat-Shamir transformation", and "Attack against weak Fiat-Shamir" protocols described above. The picture is captioned with "Fig. 1: Example weak Fiat-Shamir attack against Schnorr proofs for relation {((\mathbb{G},g),X; x) | X = g^x\}".](wFS-Schnorr-attack.png)

### References and Further Reading
[^1]: https://www.zkdocs.com/docs/zkdocs/protocol-primitives/fiat-shamir/
[^2]: Q. Dao, J. Miller, O. Wright and P. Grubbs, "Weak Fiat-Shamir Attacks on Modern Proof Systems," 2023 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2023, pp. 199-216, doi: 10.1109/SP46215.2023.10179408.
[^3]: Bernhard, D., Pereira, O., Warinschi, B. (2012). How Not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios. In: Wang, X., Sako, K. (eds) Advances in Cryptology – ASIACRYPT 2012. https://doi.org/10.1007/978-3-642-34961-4_38

