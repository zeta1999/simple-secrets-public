//! Memorable passphrase generation (BIP-39 word list).
//!
//! Secrets-grade passphrases are built by drawing uniformly random indices into
//! a word list. The default list is the full **2048-word** BIP-0039 English word
//! list (bundled verbatim in `bip39_english.txt`), giving 11 bits of entropy per
//! word — a 20-word phrase is 220 bits, a 24-word phrase 264 bits. The list spans
//! the whole alphabet, so generated phrases are not clustered on one letter.

/// The 2048-word BIP-0039 English word list, bundled verbatim (one word/line).
const WORDLIST_TXT: &str = include_str!("bip39_english.txt");

/// Returns the default 2048-word list (11 bits/word). The length is a power of
/// two, as [`select_words`] requires for unbiased selection.
pub fn default_wordlist() -> Vec<&'static str> {
    WORDLIST_TXT
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Entropy in bits provided by `count` words drawn from a list of `wordlist_len`
/// entries. Returns 0 if the list length is not a power of two (in which case
/// uniform selection via [`select_words`] is not supported).
pub fn entropy_bits(wordlist_len: usize, count: usize) -> usize {
    if wordlist_len.is_power_of_two() && wordlist_len > 1 {
        wordlist_len.trailing_zeros() as usize * count
    } else {
        0
    }
}

/// Selects `count` words by reading `log2(wordlist.len())` bits per word from
/// `random` (big-endian within the bit stream). The word list length must be a
/// power of two so every index is reachable with equal probability — otherwise
/// modulo bias would weaken the result. `random` must hold at least
/// `ceil(count * bits / 8)` bytes.
pub fn select_words(wordlist: &[&str], count: usize, random: &[u8]) -> Result<Vec<String>, String> {
    let len = wordlist.len();
    if !len.is_power_of_two() || len <= 1 {
        return Err("wordlist length must be a power of two greater than 1".to_string());
    }
    let bits = len.trailing_zeros() as usize;
    let needed_bits = count * bits;
    if random.len() * 8 < needed_bits {
        return Err(format!(
            "need {} bytes of randomness, got {}",
            needed_bits.div_ceil(8),
            random.len()
        ));
    }

    let mut out = Vec::with_capacity(count);
    let mut bit_pos = 0usize;
    for _ in 0..count {
        let mut idx = 0usize;
        for _ in 0..bits {
            let byte = random[bit_pos / 8];
            let bit = (byte >> (7 - (bit_pos % 8))) & 1;
            idx = (idx << 1) | bit as usize;
            bit_pos += 1;
        }
        out.push(wordlist[idx].to_string());
    }
    Ok(out)
}

/// Bytes of randomness required to generate `count` words from `wordlist_len`.
pub fn required_random_bytes(wordlist_len: usize, count: usize) -> usize {
    if !wordlist_len.is_power_of_two() || wordlist_len <= 1 {
        return 0;
    }
    (wordlist_len.trailing_zeros() as usize * count).div_ceil(8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn default_wordlist_is_clean() {
        let list = default_wordlist();
        assert_eq!(list.len(), 2048);
        assert!(list.len().is_power_of_two());
        let unique: HashSet<_> = list.iter().collect();
        assert_eq!(unique.len(), list.len(), "duplicate word in list");
        for w in &list {
            assert!(!w.is_empty());
            assert!(
                w.bytes().all(|b| b.is_ascii_lowercase()),
                "non-lowercase: {w}"
            );
        }
        // The whole point of using the full list: words are not all "a..." words.
        let a_words = list.iter().filter(|w| w.starts_with('a')).count();
        assert!(a_words < list.len(), "list should span beyond 'a'");
    }

    #[test]
    fn entropy_accounting() {
        assert_eq!(entropy_bits(2048, 20), 220);
        assert_eq!(entropy_bits(2048, 24), 264);
        assert_eq!(entropy_bits(100, 20), 0); // not a power of two
        assert_eq!(required_random_bytes(2048, 20), 28); // ceil(220/8)
    }

    #[test]
    fn select_words_is_deterministic_and_in_range() {
        let list = default_wordlist();
        let need = required_random_bytes(list.len(), 20);

        // 11 bits/word; all-zero bytes -> index 0 -> first word ("abandon").
        let zeros = vec![0u8; need];
        let words = select_words(&list, 20, &zeros).unwrap();
        assert_eq!(words.len(), 20);
        assert!(words.iter().all(|w| w == list[0]));

        // all-ones bytes -> index 0b111_1111_1111 == 2047 -> last word ("zoo").
        let ones = vec![0xFFu8; need];
        let words = select_words(&list, 20, &ones).unwrap();
        assert!(words.iter().all(|w| w == list[2047]));
    }

    #[test]
    fn rejects_insufficient_randomness_and_bad_list() {
        let list = default_wordlist();
        assert!(select_words(&list, 20, &[0u8; 2]).is_err());
        let three = ["a", "b", "c"];
        assert!(select_words(&three, 2, &[0u8; 8]).is_err());
    }
}
