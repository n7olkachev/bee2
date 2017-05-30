#include <stdio.h>
#include <stdlib.h>
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
        "  bels share -s <secret> -t <t> -k <k>\n"
        "  bels recover [SECRET]...\n"
        "Examples:\n"
        "  bels share -s 0123456789012345 -t 2 -k 4\n"
        "  bels recover 410C006487EC10027FBAA66DC516113DA2EF71 15800004075E3808FFCBE8E925037C13E46066\n"
    );
    return 1;
}

int recover(char** secrets, int t)
{
    char buf[256];
    octet m0[LEN];
	octet s[LEN + 1];
    octet mi[LEN * t];
    octet si[LEN * t];

    belsStdM(m0, LEN, 0);

    for (int i = 0; i < t; i++) {
        memset(buf, 0, 256);
        sscanf(secrets[i], "%6s", buf);
        hexTo(mi + i * LEN, buf);
        memset(buf, 0, 256);
        sscanf(secrets[i] + 6, "%s", buf);
        hexTo(si + i * LEN, buf);
    }

    belsRecover(s, t, LEN, si, m0, mi);

    printf("%s\n", s);
    return 1;
}

int share(int k, int t, const octet* secret)
{
    char buf[256];
    octet m0[LEN];
    octet mi[LEN * k];
    octet si[LEN * k];
    octet combo_state[512];

    if (t < 2) {
        printf("t must be > 1\n");
        return -1;
    } else if (t > 16) {
        printf("t must be < 17\n");
        return -1;
    } else if (k < 2) {
        printf("k must be > 1\n");
        return -1;
    } else if (k > 16) {
        printf("k must be < 17\n");
        return -1;
    } else if (strlen((const char *)secret) > 16) {
        printf("secret length must be < 17\n");
        return -1;
    }

	prngCOMBOStart(combo_state, utilNonce32());

    belsStdM(m0, LEN, 0);

    for (int i = 0; i < k; i++) {
        belsStdM(mi + i * LEN, LEN, i + 1);
    }
    belsShare(si, k, t, LEN, secret, m0, mi, prngCOMBOStepR, combo_state);

    for (int i = 0; i < k; i++) {
        hexFrom(buf, mi + i * LEN, LEN);
        printf("%.6s", buf);
        hexFrom(buf, si + i * LEN, LEN);
        printf("%s\n", buf);
    }

    return 1;
}

int main(int argc, char* argv[])
{
    int k = 0;
    int t = 0;
    const octet* secret = 0;

    if (argc < 2) {
        return usage();
    }
    if (strEq(argv[1], "share")) {
        if (argc != 8) {
            return usage();
        }
        for (int i = 2; i < 8; i += 2) {
            if (strEq(argv[i], "-k")) {
                k = strtol(argv[i + 1], NULL, 10);
            } else if (strEq(argv[i], "-t")) {
                t = strtol(argv[i + 1], NULL, 10);
            } else if (strEq(argv[i], "-s")) {
                secret = (const octet*)argv[i + 1];
            }
        }

        return share(k, t, secret);
    } else if (strEq(argv[1], "recover")) {
        if (argc < 4) {
            return usage();
        }

        return recover(argv + 2, argc - 2);
    } else {
        return usage();
    }

}
