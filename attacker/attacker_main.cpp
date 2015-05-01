#include "attacker.h"

using aitf::Attacker;

int main(int argc, char *argv[]) {
    Attacker attacker(AITF_SNEAKY);
    printf("IMMA CHARGIN MAH LAZOR\n");
    attacker.fire_lazor();
    attacker.loop();
    return 0;
}
