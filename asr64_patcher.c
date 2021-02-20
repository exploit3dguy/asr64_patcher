#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define GET_OFFSET(len, x) (x - (uintptr_t) asr)

typedef unsigned long long addr_t;

static uint32_t arm64_branch_instruction(uintptr_t from, uintptr_t to) {
  return from > to ? 0x18000000 - (from - to) / 4 : 0x14000000 + (to - from) / 4;
}

// thanks xerub for xref64

static addr_t
xref64(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            continue;				// XXX should not XREF on its own?
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        /*} else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[rn] = value[rn] + imm;	// XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
        if (value[reg] == what) {
            return i;
        }
    }
    return 0;
}

void exception() {
        printf("exploit3d exception = what????\n");
    	exit(1);
}


int get_asr_patch(void *asr, size_t len) {

	printf("getting %s()\n", __FUNCTION__);

	void *failed = memmem(asr,len,"Image failed signature verification", strlen("Image failed signature verification"));
    if (!failed) {
    	exception();
    }

	printf("[*] Image failed signature verification %p\n", failed);

    void *passed = memmem(asr,len,"Image passed signature verification", strlen("Image passed signature verification"));

    if (!passed) {
    	exception();
    }

    printf("[*] Image passed signature verification %p\n", passed);

    addr_t ref_failed = xref64(asr,0,len,(addr_t)GET_OFFSET(len, failed));
    
    if(!ref_failed) {
    	exception();
    }

    addr_t ref_passed = xref64(asr,0,len,(addr_t)GET_OFFSET(len, passed));
    
    if(!ref_passed) {
    	exception();
    }

    printf("[*] Assembling arm64 branch\n");

    uintptr_t ref1 = (uintptr_t)ref_failed;
 
    uintptr_t ref2 = (uintptr_t)ref_passed;

    uint32_t our_branch = arm64_branch_instruction(ref1, ref2);

    *(uint32_t *) (asr + ref_failed) = our_branch;

    return 0;

}


int main(int argc, char* argv[]) { 

	if (argc < 3) {
		printf("asr_patcher - easily patch ASR on 64-bit devices. By Exploit3d.\n");
		printf("Usage: asr asr_patched\n");
		return -1;
	}

	char *in = argv[1];
	char *out = argv[2];

	void *asr;
	size_t len;

	 FILE* fp = fopen(in, "rb");
     if (!fp) {
     	printf("[-] Failed to open ASR\n");
     	return -1;
     }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    asr = (void*)malloc(len);
    if(!asr) {
        printf("[-] Out of memory\n");
        fclose(fp);
        return -1;
    }

    fread(asr, 1, len, fp);
    fclose(fp);

    get_asr_patch(asr,len);


    printf("[*] Writing out patched file to %s\n", out);

    fp = fopen(out, "wb+");

    fwrite(asr, 1, len, fp);
    fflush(fp);
    fclose(fp);
    
    free(asr);

    
    return 0;

}
