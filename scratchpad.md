# DES Implementation Scratchpad

Before we start implementing DES, we need to know what it is...

Imagine you have a 64 bit plaintext message and a 64 bit key, the main goal of DES is to encrypt this plaintext message using the key so no body can figure out the original message unless they have the key.

But wait... DES doesn't just move bits randomly, it uses a precise series of bit rearrangements (permutations), mixing (XORs) and lookups (substitution boxes) to make your message unreadable.

## Methodology

### Initial Permutation (IP)

The first step in DES is the Initial Permutation (IP), its like shuffling the 64 bits of plaintext into a new order before starting the main encryption process.

This is done to ensure that the bits are mixed up right from the start.

So we must apply initialPerm() at the beginning of our DES implementation.

After doing IP, the 64 bit plaintext is split into two 32 bit halves which are called LPT and RPT.

These halves will be used in the feistel rounds.

### Preparing the key schedule

Now, we will begin to prepare the round keys that will be used in encryption process.

1. We first apply the key permutation (PC1) to the 64 bit key to get a 56 bit key.
2. Then, we split this 56 bit key into two 28 bit halves (C and D).
3. For each of the 16 rounds, both halves (C and D) are shifted to the left (circularly), using the value from keyShifts[] for that round
4. After shifting, we combine C and D to make a 64 bit key value and then use pc2 to permute it into a 48 bit round key, this will give us the round key for that round. PC2 does compression of the key bit taking input of 56 bits and generating 48 bits.

After we have all 16 round keys, we can start the main encryption process.

### The 16 Feistel Rounds

Now we are ready to start the main encryption process using the 16 Feistel rounds.

for each round, we will do the following:

We will take the RPT (32 bits) and expand it to 48 bits using the expansionPerm() table.

Then we will XOR the expanded RPT with the 48 bit round key for that round.

Next, this 48 bit result is split into 8 groups of 6 bits, each group goes through its own S-Box in sBoxes[], which replace the 6 input bits with 4 output bits, this really confuse attackers!

Then, the eight 4 bit outputs are then joined together to make a new 32 bit value.

Now, we start with the S-box permutation (p-box), we permute the 32 bits output from the s boxes using sboxPerm() table, this further mix the bits so that changing 1 input bit affects many output bits, increasing diffusion.

Lastly, the result of the permutation is XORed with the current LPT (32 bits) to get the new RPT for this round.

And for the next round, the new left half (LPT) becomes the current right half (RPT) and the new right half (RPT) becomes the result of the XOR operation (left ^ feistel output).

This swap is what makes it a Feistel cipher: only one half goes through the complex transformation each round, and the two halves swap roles.

This is repeated for all 16 rounds and each time using the round key for that round.

### Final Permutation

After the 16th round, we swap the left and right halves one last time.

Then we join them into a single 64 bit block and apply the finalPerm permutation using finalPerm() table, this is the last shuffle of the bits, giving us the final ciphertext!
