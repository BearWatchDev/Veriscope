"""
Repeating-key XOR breaker using frequency analysis and crib-dragging
"""

import string
from typing import List, Tuple, Optional
from collections import Counter


class XORBreaker:
    """Break repeating-key XOR using frequency analysis"""

    # English letter frequency (most common letters)
    ENGLISH_FREQ = {
        'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
        'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
        'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
        'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29
    }

    # Common cribs for probable-plaintext attacks
    CRIBS = [
        "powershell", "SELECT", "http", "https", "svc_", "token", "jwt",
        ".exe", "certutil", "nc", "password", "admin", "cmd", "bash",
        "wget", "curl", "echo", "eval", "exec", "shell", "payload",
        "script", "user", "root", "api", "key", "secret"
    ]

    def __init__(self, max_key_len: int = 12):
        self.max_key_len = max_key_len

    def score_english(self, text: str) -> float:
        """Score text based on word presence and vowel ratio (simpler, faster)"""
        if not text:
            return 0.0

        text_lower = text.lower()

        # Word presence scoring (more reliable than letter frequency)
        word_score = 0.0
        words = [" the ", " and ", " http", " select", " password", " shell",
                 " nc ", " admin", " user", " token", " key ", " cmd", " exec"]
        for word in words:
            if word in text_lower:
                word_score += 2.0

        # Vowel ratio (English text typically 35-45% vowels)
        if len(text) > 0:
            vowels = sum(text_lower.count(v) for v in "aeiou")
            vowel_ratio = (vowels / len(text)) * 10.0
        else:
            vowel_ratio = 0.0

        return word_score + vowel_ratio

    def printable_ratio(self, text: str) -> float:
        """Calculate ratio of printable characters"""
        if not text:
            return 0.0
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return printable / len(text)

    def hamming_distance(self, bytes1: bytes, bytes2: bytes) -> int:
        """Calculate Hamming distance between two byte strings"""
        dist = 0
        for b1, b2 in zip(bytes1, bytes2):
            xor = b1 ^ b2
            dist += bin(xor).count('1')
        return dist

    def guess_key_length(self, ciphertext: bytes) -> List[int]:
        """Guess probable key lengths using normalized Hamming distance"""
        if len(ciphertext) < 40:
            return list(range(1, min(len(ciphertext) // 4, self.max_key_len) + 1))

        distances = []

        for keysize in range(1, min(self.max_key_len + 1, len(ciphertext) // 4)):
            # Take 4 blocks of keysize
            blocks = []
            for i in range(4):
                start = i * keysize
                end = start + keysize
                if end <= len(ciphertext):
                    blocks.append(ciphertext[start:end])

            if len(blocks) < 2:
                continue

            # Calculate average normalized Hamming distance
            dist_sum = 0
            count = 0
            for i in range(len(blocks)):
                for j in range(i + 1, len(blocks)):
                    dist_sum += self.hamming_distance(blocks[i], blocks[j]) / keysize
                    count += 1

            if count > 0:
                avg_dist = dist_sum / count
                distances.append((keysize, avg_dist))

        # Sort by distance (lower is better)
        distances.sort(key=lambda x: x[1])

        # Return top 5 key lengths
        return [keysize for keysize, _ in distances[:5]]

    def break_single_byte_xor(self, ciphertext: bytes) -> Tuple[int, str, float]:
        """Break single-byte XOR, return (key, plaintext, score)"""
        best_score = 0
        best_key = 0
        best_text = ""

        for key in range(256):
            try:
                plaintext = bytes(b ^ key for b in ciphertext).decode('utf-8', errors='ignore')

                # Score based on English frequency + printable ratio
                english_score = self.score_english(plaintext)
                printable = self.printable_ratio(plaintext)

                # Combined score (weighted)
                score = english_score * 0.6 + printable * 0.4

                if score > best_score:
                    best_score = score
                    best_key = key
                    best_text = plaintext
            except:
                continue

        return best_key, best_text, best_score

    def break_repeating_key_xor(self, ciphertext: bytes) -> List[Tuple[bytes, str, float]]:
        """
        Break repeating-key XOR using position-based brute force
        More robust than Hamming distance approach
        Returns list of (key, plaintext, score) tuples, sorted by score
        """
        results = []

        # Try all key lengths from 1 to max_key_len
        for keylen in range(1, min(self.max_key_len + 1, len(ciphertext) // 2)):
            # For each position in the key, brute force all 256 possibilities
            key = bytearray()

            for pos in range(keylen):
                # Extract every keylen-th byte starting at pos
                block = ciphertext[pos::keylen]

                # Brute force this position only
                best_byte = 0
                best_score = -1.0

                for candidate_byte in range(256):
                    # Decrypt this block with candidate byte
                    decrypted_block = bytes(b ^ candidate_byte for b in block)

                    # Score this block
                    try:
                        text = decrypted_block.decode('utf-8', errors='ignore')
                        printable = self.printable_ratio(text)
                        english = self.score_english(text)
                        score = printable * 0.5 + english * 0.5

                        if score > best_score:
                            best_score = score
                            best_byte = candidate_byte
                    except:
                        continue

                key.append(best_byte)

            # Decrypt full ciphertext with discovered key
            key_bytes = bytes(key)
            try:
                plaintext_bytes = bytes(
                    ciphertext[i] ^ key_bytes[i % len(key_bytes)]
                    for i in range(len(ciphertext))
                )
                plaintext = plaintext_bytes.decode('utf-8', errors='ignore')

                # Score the full result
                english_score = self.score_english(plaintext)
                printable = self.printable_ratio(plaintext)
                combined_score = english_score * 0.3 + printable * 0.7

                # Check for cribs (bonus score)
                crib_bonus = 0.0
                for crib in self.CRIBS:
                    if crib.lower() in plaintext.lower():
                        crib_bonus += 0.2

                final_score = min(1.0, combined_score + crib_bonus)

                results.append((key_bytes, plaintext, final_score))
            except:
                continue

        # Sort by score (descending)
        results.sort(key=lambda x: x[2], reverse=True)

        return results[:5]  # Return top 5 candidates

    def crib_drag(self, ciphertext: bytes, cribs: List[str] = None) -> List[Tuple[bytes, str, str]]:
        """
        Crib-dragging attack: try known plaintext cribs to find key
        Returns list of (key, plaintext, matched_crib) tuples
        """
        if cribs is None:
            cribs = self.CRIBS

        results = []

        for crib in cribs:
            crib_bytes = crib.encode('utf-8')

            # Try XORing crib at each position
            for pos in range(len(ciphertext) - len(crib_bytes) + 1):
                # Extract key fragment
                key_fragment = bytes(
                    ciphertext[pos + i] ^ crib_bytes[i]
                    for i in range(len(crib_bytes))
                )

                # Try to extend key (assume repeating)
                for keylen in [1, 2, 3, 4, len(key_fragment)]:
                    if keylen > len(key_fragment):
                        continue

                    # Take first keylen bytes as repeating key
                    key = key_fragment[:keylen]

                    # Decrypt entire ciphertext
                    try:
                        plaintext_bytes = bytes(
                            ciphertext[i] ^ key[i % len(key)]
                            for i in range(len(ciphertext))
                        )
                        plaintext = plaintext_bytes.decode('utf-8', errors='ignore')

                        # Check if plaintext looks good
                        printable = self.printable_ratio(plaintext)
                        if printable > 0.7 and crib.lower() in plaintext.lower():
                            results.append((key, plaintext, crib))
                    except:
                        continue

        # Deduplicate and return unique results
        seen = set()
        unique_results = []
        for key, plaintext, crib in results:
            if plaintext not in seen:
                seen.add(plaintext)
                unique_results.append((key, plaintext, crib))

        return unique_results[:5]  # Return top 5

    def try_common_single_byte_xor(self, ciphertext: bytes) -> List[Tuple[int, str, float]]:
        """Try common single-byte XOR keys first (fast path)"""
        common_bytes = [0x5A, 0x20, 0xFF, 0xAA, 0x55, 0x00, 0x01, 0x42, 0x13]
        results = []

        for key_byte in common_bytes:
            try:
                plaintext_bytes = bytes(b ^ key_byte for b in ciphertext)
                plaintext = plaintext_bytes.decode('utf-8', errors='ignore')

                printable = self.printable_ratio(plaintext)
                english = self.score_english(plaintext)
                score = printable * 0.6 + english * 0.4

                # Check for cribs
                crib_found = any(crib.lower() in plaintext.lower() for crib in self.CRIBS)
                if crib_found:
                    score += 0.3

                if score > 0.5:
                    results.append((key_byte, plaintext, score))
            except:
                continue

        results.sort(key=lambda x: x[2], reverse=True)
        return results[:3]

    def try_common_keys(self, ciphertext: bytes) -> List[Tuple[bytes, str, float]]:
        """Try common multibyte XOR keys found in the wild"""
        common_keys = [
            b"test", b"key", b"admin", b"password", b"secret",
            b"abc", b"xyz", b"1234", b"0000", b"\x00\x01",
            b"Veris", b"veriscope", b"malware"
        ]

        results = []

        for key in common_keys:
            try:
                plaintext_bytes = bytes(
                    ciphertext[i] ^ key[i % len(key)]
                    for i in range(len(ciphertext))
                )
                plaintext = plaintext_bytes.decode('utf-8', errors='ignore')

                # Score
                printable = self.printable_ratio(plaintext)
                english = self.score_english(plaintext)
                score = printable * 0.5 + english * 0.5

                if score > 0.5:
                    results.append((key, plaintext, score))
            except:
                continue

        results.sort(key=lambda x: x[2], reverse=True)
        return results[:3]
