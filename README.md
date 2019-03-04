# goBitcoinParser
Parser of Bitcoin .dat files written in Go language

[Link for blk00000.dat file](https://drive.google.com/file/d/1md2xNb4H3LpJM_lWhVzijqjN0zR2fk4C/view?usp=sharing)

TODO:
1. Input/Output Script decoding
2. Insert into db / save in CSV format
3. Sort Blocks according to Previous Block Hash
4. Decrease Memory Usage (Currently ~400 Megs total allocation for 128 Meg dat file)
5. Add SegWit Support
6. Make parser parse full blocks folder
7. Make parser multithreaded
