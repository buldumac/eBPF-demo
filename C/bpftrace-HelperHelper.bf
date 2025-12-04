bpftrace -e '
uprobe:./lots-of-hello:HelperHelper {
    printf("arg: %d\n", arg0);
}

uretprobe:./lots-of-hello:HelperHelper {
    printf("text: %s\n", str(retval));
}
'
