#ifndef SAM_H
#define SAM_H

#define HASH_SIZE 243
#define STATE_SIZE 729
#define NUMBER_OF_ROUNDS 9
#define DELTA 364


struct SaM {
    int F[9];
    int state[STATE_SIZE];
    int leftPart[STATE_SIZE], rightPart[STATE_SIZE];
};

void init_SaM(struct SaM *s);
void reset(struct SaM *s);
void absorb(struct SaM *s, int *input, int offset, int length);
void squeeze(struct SaM *s, int *output, int offset);
#endif
