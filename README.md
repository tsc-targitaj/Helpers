# Собираю здесь всякие наработки, заготовки и полезности.

// формат date

```
echo "Now `date +"%Y-%m-%d_%H-%M-%S_%Z"`"
```
// percent decode
```
alias urldecode='sed "s@+@ @g;s@%@\\\\x@g" | xargs -0 printf "%b"'
```
