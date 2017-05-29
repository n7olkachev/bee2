#include <stdio.h>
#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>
#define LEN 16

int usage()
{
    printf(
        "Usage:\n"
        "  bels share -- share secret\n"
        "  bels recover -- recover secret\n"
    );
    return 1;
}

int recover()
{
    int t = 0;
    char buf[256];
    octet m0[LEN];
	octet s[LEN + 1];

    memset(buf, 0, 256);
    memset(buf, 0, LEN + 1);

    printf("T = ");
    scanf("%d", &t);
    printf("M0 = ");
    scanf("%s", buf);
    hexTo(m0, buf);

	octet* mi = malloc(sizeof(octet) * LEN * t * 5);
	octet* si = malloc(sizeof(octet) * LEN * t * 5);

    for (int i = 0; i < t; i++) {
        printf("M%d = ", i + 1);
        scanf("%s", buf);
        hexTo(mi + i * LEN, buf);
        printf("S%d = ", i + 1);
        scanf("%s", buf);
        hexTo(si + i * LEN, buf);
    }

    belsRecover(s, t, LEN, si, m0, mi);

    printf("Secret: %s\n", s);
    return 1;
}

int share()
{
    char buf[256];
    int k = 0;
    int t = 0;
    char secret[LEN + 1];
	octet m0[LEN];
	octet s[LEN];
    octet combo_state[512];

    memset(secret, 0, LEN + 1);

    printf("Secret (max length: %d): ", LEN);
    scanf("%s", secret);
    printf("K = ");
    scanf("%d", &k);
    printf("T = ");
    scanf("%d", &t);
    printf("\n");

	octet* mi = malloc(sizeof(octet) * LEN * k);
	octet* si = malloc(sizeof(octet) * LEN * k);

	prngCOMBOStart(combo_state, utilNonce32());

    belsGenM0(m0, LEN, prngCOMBOStepR, combo_state);
    hexFrom(buf, m0, LEN);
    printf("M0:\t%s\n\n", buf);

    for (int i = 0; i < k; i++) {
        belsGenMi(mi + i * LEN, LEN, m0, prngCOMBOStepR, combo_state);
    }
    belsShare(si, k, t, LEN, secret, m0, mi, prngCOMBOStepR, combo_state);

    for (int i = 0; i < k; i++) {
        hexFrom(buf, mi + i * LEN, LEN);
        printf("M%d:\t%s\n", i + 1, buf);
        hexFrom(buf, si + i * LEN, LEN);
        printf("S%d:\t%s\n\n", i + 1, buf);
    }

    return 1;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        return usage();
    }
    if (strEq(argv[1], "share")) {
        return share();
    } else if (strEq(argv[1], "recover")) {
        return recover();
    } else {
        return usage();
    }

}
