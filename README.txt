TO COMPILE APPLICATION USE NEXT STEPS:
1. build cppcrypto library
2. g++ -g -std=gnu++11 -fpermissive -I${PWD}/cppcrypto/cppcrypto/ -I/${PWD}/cppcrypto/cppcrypto/ -o  main ${PWD}/src/main.cpp -L${PWD}/cppcrypto/cppcrypto/ -lcppcrypto
