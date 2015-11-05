/*
 * Ported from original Java to C By BTCDDev
*/


/**
 * (c) 2015 Come-from-Beyond
 *
 * SaM - fast and simple cryptographic hash function for trinary-based hardware/software
 *
 * A 243-trit hash function based on the sponge construction. Its transformation function exhibits properties of
 * the ideal transformation function to the following degree (the data were obtained after 100'000'000 test iterations,
 * the corresponding values of the ideal function are shown in parentheses):
 *
 * Number of changed trits after applying the transformation function on two states having a difference in a single trit
 * (avalanche effect) has a binomial distribution with
 * mean = 486.000369 (486.000000),
 * variance = 162.003272 (162.000000),
 * skewness = -0.026309 (0.000000),
 * kurtosis = 0.000569 (0.000000).
 *
 * Correlation between input and output trits (trit independence) measured as the maximum number of changes of a single
 * trit divided by the minimum number of changes of a single trit = 1.000460 (1.000000).
 *
 * Correlation between output trits (trit independence) measured as the maximum number of changes of a single trit
 * divided by the minimum number of changes of a single trit
 * excluding the same trit = 1.001003 (1.000000),
 * including the same trit = 1.501088 (1.500000).
 *
 * Percentage of sequences with the same trit values
 * for 1-trit long sequences = 66.7126% (66.6667%),
 * for 2-trit long sequences = 22.2070% (22.2222%),
 * for 3-trit long sequences = 7.3920% (7.4074%),
 * for 4-trit long sequences = 2.4606% (2.4691%),
 * for 5-trit long sequences = 0.8191% (0.8230%),
 * for 6-trit long sequences = 0.2727% (0.2743%),
 * for 7-trit long sequences = 0.0908% (0.0914%),
 * for 8-trit long sequences = 0.0302% (0.0305%),
 * for 9-trit long sequences = 0.0101% (0.0102%),
 * for the sequences of the other lengths = 0.0050% (0.0051%).
 *
 * Uniformity of different trit combinations measured as the number of the most often seen combination divided by
 * the number of the least seen combination
 * for 1-trit long combinations = 1.000021 (1.000000),
 * for 2-trit long combinations = 1.000054 (1.000000),
 * for 3-trit long combinations = 1.000086 (1.000000),
 * for 4-trit long combinations = 1.000149 (1.000000),
 * for 5-trit long combinations = 1.000295 (1.000000),
 * for 6-trit long combinations = 1.000625 (1.000000),
 * for 7-trit long combinations = 1.001220 (1.000000),
 * for 8-trit long combinations = 1.002416 (1.000000),
 * for 9-trit long combinations = 1.004473 (1.000000).
 *
 * Before using SaM for hashing data must be converted into balanced trinary numeral system with trits stored as
 * an array of ints. The state and output are represented in the same form.
 *
 * Function reset() is used to reset the state before computing a new hash, after that absorb() is used to absorb
 * all input data, squeeze() can be used several times to generate pseudorandom sequence of an arbitrary length.
 *
 * To use SaM as a cryptographic hash function the state should be initialized with one or more non-zero trits put
 * starting from index 243+. The author recommends to put there the length of data that is being absorbed to counteract
 * slide attacks and to generate different hashes for inputs that differ only in the number of zeros in the end. Note
 * that the hash of the empty string is all zeros, this can be used in cases when the hash of NULL should be NULL.
 *
 * If SaM is used to generate proof-of-work tokens then it should be taken into account that computation of a single
 * trit of the state after a transformation requires at least 9771 invocations of f() if the time-memory trade-off is
 * exploited. By comparing this number to the number of f() invocations for all trits of the state (19683), we see that
 * the minimum number of the invocations is 49.6% of the total number. The leverage is reduced to at least 50% for
 * 6 consecutive trits, 243 consecutive trits require more than 68% invocations. Computation of all 729 trits gets
 * no benefit from the time-memory trade-off.
 *
 * SaM can be used in several ways similar to Keccak.
 *
 * The author would like to thank the creators of Keccak and the sponge construction which inspired creation of SaM.
 */

#include <string.h>
#include "SaM.h"

void init_SaM(struct SaM *s)
{
    memcpy(s->F, (int[9]){0, -1, 1, 0, 1, -1, -1, 1, 0}, 9*sizeof(int));
    memset(s->state,     0, STATE_SIZE*sizeof(int));
    memset(s->leftPart,  0, STATE_SIZE*sizeof(int));
    memset(s->rightPart, 0, STATE_SIZE*sizeof(int));
}

void reset(struct SaM *s) {
    memset(s->state, 0, STATE_SIZE*sizeof(int));
}

static int nextIndex(int index) {
    return (index + DELTA) % STATE_SIZE;
}

static int f(struct SaM *s, int a, int b) {
    return s->F[(a + 1) * 3 + (b + 1)];
}


static void transform(struct SaM *s) {

	int i, round, index = 0;
	for (round = 0; round < NUMBER_OF_ROUNDS; round++) {

    	for (i = 0; i < STATE_SIZE; i++) {

		    int nextInd = nextIndex(index);
			int temp = f(s, s->state[index], s->state[nextInd]);
			s->leftPart[i] = temp;
			temp = f(s, s->state[nextInd], s->state[index]);
		    s->rightPart[i] = temp;
		    index = nextInd;
		}

		for (i = 0; i < STATE_SIZE; i++) {
		    int nextInd = nextIndex(index);
			int temp = f(s, s->leftPart[index], s->rightPart[nextInd]);
			s->state[i] = temp;
		    index = nextInd;
		}
	}
}

void absorb(struct SaM *s, int *input, int offset, int length) {
	int i, remainder = length;
	do {
	    for (i = (remainder >= HASH_SIZE ? HASH_SIZE : remainder); i-- > 0; ) {
        	s->state[i] = input[offset + (length - remainder) + i];
        }
        remainder -= HASH_SIZE;
        transform(s);
    } while (remainder > 0);
}

void squeeze(struct SaM *s, int *output, int offset) {
	int i;
	for (i = HASH_SIZE; i-- > 0; ) {
	    output[offset + i] = s->state[i];
    }
    transform(s);
}

