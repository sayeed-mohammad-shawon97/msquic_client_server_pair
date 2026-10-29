create client.c and server.c files and add it to cmake lists, you can use quicsample's cmake list and place the files in the same directory
Create a directory for the signature and the text file for transmission.
Generate a self signed certificate for the lab with:

        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -nodes -keyout key.pem -out cert.pem -days 30 \
            -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
in the same directory as keys create a folder named "www". 
place your text file as hello.txt inside www folder.
build the msquic library with tools enabled
set BIN= "your msquic build directory" mine is BIN=~/CLionProjects/msquic/build/bin/Release
each new terminal requires to set BIN
Run the server from the directory that contains cert.pem, key.pem and www/.
for the client, open a new terminal and set the bin again and run the client.

# terminal 1
$BIN/quicserver

# terminal 2
$BIN/quicclient
