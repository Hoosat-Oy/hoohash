# hoohash

Hoohash is Hoosat Network's own algorithm, read the Hoohash code for more information currently. Documentation to be done.


## Dynamic library compilation

Just do `make` and `make clean` or if you want to compile yourself with gcc:

```
gcc -fPIC -shared -o lib-hoohash.so hoohash.c bigint.c
```
