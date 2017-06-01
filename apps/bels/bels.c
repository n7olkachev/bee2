#include <stdio.h>
#include <stdlib.h>
#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>

static const char hex_upper[] = "0123456789ABCDEF";
static const char hex_lower[] = "0123456789abcdef";

static const octet hex_dec_table[256] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

static octet hexToO(const char* hex)
{
	register octet hi;
	register octet lo;
	ASSERT(memIsValid(hex, 2));
	hi = hex_dec_table[(octet)hex[0]];
	lo = hex_dec_table[(octet)hex[1]];
	ASSERT(hi != 0xFF && lo != 0xFF);
	return hi << 4 | lo;
}

static void hexFromOUpper(char* hex, register octet o)
{
	ASSERT(memIsValid(hex, 2));
	hex[0] = hex_upper[o >> 4];
	hex[1] = hex_upper[o & 15];
	o = 0;
}

int usage()
{
    printf(
        "Usage:\n"
        "  bels share -s <secret> -t <t> -k <k>\n"
        "    secret - secret string in hex representation"
        "    t - minimal amount of secret parts to recover secret"
        "    k - total amount of secret parts"
        "  bels recover [SECRET]...\n"
        "Examples:\n"
        "  bels share -s 30313233343536373839313233343536 -t 2 -k 4\n"
        "  bels recover 410C006487EC10027FBAA66DC516113DA2EF71 15800004075E3808FFCBE8E925037C13E46066\n"
    );
    return 1;
}

int recover(char** secrets, int t)
{
    const int len = (strlen(secrets[0]) - 2) / 2;
    int miNum = 0;
    char buf[256];
    octet m0[len];
	octet s[len + 1];
    octet mi[len * t];
    octet si[len * t];

    for (int i = 0; i < t; i++) {
        if (!hexIsValid(secrets[i])) {
            printf("secret parts must be a hex string\n");
            return -1;
        }
    }
    for (int i = 0; i < t; i++) {
        for (int j = i + 1; j < t; j++) {
            if (strlen(secrets[i]) != strlen(secrets[j])) {
                printf("secret parts must have same length\n");
                return -1;
            } else if (secrets[i][0] == secrets[j][0] && secrets[i][1] == secrets[j][1]) {
                printf("secret parts must have unique signatures\n");
                return -1;
            }
        }
    }

    belsStdM(m0, len, 0);

    for (int i = 0; i < t; i++) {
        miNum = hexToO(secrets[i]);
        if (miNum < 0 || miNum > 16) {
            printf("wrong signature!\n");
            return -1;
        }
        belsStdM(mi + i * len, len, miNum);
        memset(buf, 0, 256);
        sscanf(secrets[i] + 2, "%s", buf);
        hexTo(si + i * len, buf);
    }

    belsRecover(s, t, len, si, m0, mi);

    hexFrom(buf, s, len);

    printf("%s\n", buf);
    return 1;
}

int share(int k, int t, const octet* secret)
{
    const int len = strlen((const char*)secret) / 2;
    char buf[256];
    octet secretData[len];
    octet m0[len];
    octet mi[len * k];
    octet si[len * k];
    octet rngState[512];
    octet rngBuf[2500];
	size_t rngRead;
    char hex[2];
    memset(buf, 0, 256);

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
    } else if (t > k) {
        printf("t must be <= k\n");
        return -1;
    } else if (len != 16 && len != 24 && len != 32) {
        printf("secret length must equals 16 or 24 or 32 bytes\n");
        return -1;
    } else if (!hexIsValid((const char *)secret)) {
        printf("secret must be a hex string\n");
        return -1;
    }

    hexTo(secretData, (const char*)secret);

	rngCreate(0, rngState);

    belsStdM(m0, len, 0);

    for (int i = 0; i < k; i++) {
        belsStdM(mi + i * len, len, i + 1);
    }
    belsShare(si, k, t, len, secretData, m0, mi, rngStepR, rngState);

    for (int i = 0; i < k; i++) {
        hexFrom(buf, si + i * len, len);
        hexFromOUpper(hex, i + 1);
        printf("%.2s%s\n", hex, buf);
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
