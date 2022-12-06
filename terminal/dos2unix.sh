#!/bin/bash

echo "Working alias dos2unix for you..."
grep "alias dos2unix" ~/.bashrc 2>&1 >/dev/null && echo "You already have it." && exit 0
echo 'alias dos2unix="sed -i -e 's/'\"\$(printf '\015')\"'//g' "' | tee -a ~/.bashrc
echo "Added alias dos2unix to file ~/.bashrc"
echo "Usage: dos2unix file"
