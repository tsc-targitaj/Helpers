#!/bin/sh

echo 'alias dos2unix="sed -i -e 's/'\"\$(printf '\015')\"'//g' "' | tee -a ~/.bashrc
echo "Added alias dos2unix to file ~/.bashrc"
echo "Usage: dos2unix file"
