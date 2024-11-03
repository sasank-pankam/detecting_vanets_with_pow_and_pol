import hashlib
import random

from bls12381 import big, curve, ecp, ecp2, pair


def modinv(a, p):
    """Return the modular inverse of a modulo p."""
    if a == 0:
        raise ValueError("Modular inverse does not exist for zero.")

    # Extended Euclidean Algorithm
    original_p = p
    x0, x1 = 0, 1
    while a > 1:
        q = a // p
        p, a = a % p, p
        x0, x1 = x1 - q * x0, x0

    if x1 < 0:
        x1 += original_p

    return x1


class ThresholdBLS:
    def __init__(self, t, n):
        """
        Initialize threshold signature scheme with threshold t and n participants
        t: threshold (minimum signatures needed)
        n: total number of participants
        """
        self.t = t  # threshold
        self.n = n  # total participants
        self.order = curve.r  # curve order

        # Generate polynomial coefficients for secret sharing
        self.coefficients = [big.rand(self.order) for _ in range(t)]
        self.master_secret = self.coefficients[0]  # a0 is the master secret

        # Generate master public key using the generator point
        G = ecp2.generator()  # Get the generator point of G2
        self.master_public_key = self.master_secret * G

        # Generate shares for each participant
        self.shares = []  # secret shares
        self.public_shares = []  # public shares

        for i in range(1, n + 1):
            # Evaluate polynomial at point i
            share = self.compute_share(i)
            self.shares.append(share)
            # Compute public share
            public_share = share * G
            self.public_shares.append(public_share)
        # print(self.shares)
        # print("\n".join(map(str, self.shares)))

    def compute_share(self, x):
        """Compute the secret share for participant x using polynomial evaluation"""
        result = self.coefficients[0]
        power = x

        for i in range(1, self.t):
            term = big.modmul(self.coefficients[i], power, self.order)
            result = big.modadd(result, term, self.order)
            power = big.modmul(power, x, self.order)

        return result

    def hash_message(self, message):
        """Hash message to point on G1"""
        G1 = ecp.generator()  # Get the generator point of G1
        msg_hash = hashlib.sha256(f"{message}".encode()).digest()
        # Convert hash to a point on G1 (Note: This is a simplified approach)
        h = big.from_bytes(msg_hash) % self.order
        return h * G1

    def sign_share(self, participant_idx, message):
        """Generate signature share for a participant"""
        if participant_idx >= self.n:
            raise ValueError("Invalid participant index")

        H_m = self.hash_message(message)
        share = self.shares[participant_idx]
        return share * H_m

    def compute_lagrange_coeff(self, indices):
        """Compute Lagrange coefficients for reconstruction"""
        if len(indices) < self.t:
            raise ValueError(f"Need at least {self.t} shares for reconstruction")

        coeffs = []
        for i in indices:
            numerator = 1
            denominator = 1
            for j in indices:
                if i != j:
                    numerator = big.modmul(numerator, j + 1, self.order)
                    diff = big.modsub(j + 1, i + 1, self.order)
                    denominator = big.modmul(denominator, diff, self.order)

            coeff = big.modmul(numerator, modinv(denominator, self.order), self.order)
            coeffs.append(coeff)

        return coeffs

    def combine_signatures(self, sig_shares, indices):
        """Combine signature shares into final signature"""
        if len(sig_shares) < self.t:
            raise ValueError(f"Need at least {self.t} signature shares")

        lagrange_coeffs = self.compute_lagrange_coeff(indices)

        # Initialize with first share * coefficient
        combined_sig = lagrange_coeffs[0] * sig_shares[0]

        # Add remaining shares
        for i in range(1, len(sig_shares)):
            term = lagrange_coeffs[i] * sig_shares[i]
            combined_sig.add(term)

        return combined_sig

    def verify_share(self, participant_idx, message, signature_share):
        """Verify a signature share"""
        H_m = self.hash_message(message)
        public_share = self.public_shares[participant_idx]
        G2 = ecp2.generator()

        # Check e(H(m), PKi) = e(σi, g2)
        lhs = pair.ate(public_share, H_m)
        rhs = pair.ate(G2, signature_share)
        lhs = pair.fexp(lhs)
        rhs = pair.fexp(rhs)

        return lhs == rhs

    def verify_signature(self, message, signature):
        """Verify the combined signature"""
        H_m = self.hash_message(message)
        G2 = ecp2.generator()

        # Check e(H(m), PK) = e(σ, g2)
        lhs = pair.ate(self.master_public_key, H_m)
        rhs = pair.ate(G2, signature)
        lhs = pair.fexp(lhs)
        rhs = pair.fexp(rhs)

        return lhs == rhs

    def sign_with_master_key(self, message):
        """Sign a message using the master secret key directly."""
        H_m = self.hash_message(message)
        return self.master_secret * H_m  # Signature using the master secret key

    def verify_combined_signature_with_master_key(self, message, combined_signature):
        """Check if the combined signature matches the signature generated with the master key."""
        signature_with_master_key = self.sign_with_master_key(message)
        return combined_signature == signature_with_master_key
