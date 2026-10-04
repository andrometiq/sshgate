#!/bin/sh
# Drain every input first, like the grep/diff it stands in for: zgrep and zdiff
# report a decompressor that hit a closed pipe as status 2.
for operand do
	case $operand in /dev/fd/*) cat -- "$operand" > /dev/null ;; esac
done
cat > /dev/null
: > "$SINK"
