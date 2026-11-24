/* Leak detection is not what this fleet fuzzes for; ASan + UBSan stay fully active (SPEC §6.2 item 15). */
int __lsan_is_turned_off(void);
int __lsan_is_turned_off(void) { return 1; }
