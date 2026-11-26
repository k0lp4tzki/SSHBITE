while IFS= read -r n; do getent hosts "$n" | awk -v n="$n" '{print n"\t"$1}'; done
