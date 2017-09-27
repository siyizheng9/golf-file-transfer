# golf-file-transfer

A simple C based FTP-like server and client, written as a course project.

## Compile

Go to `./src` folder: `make all`

## Usage

Start server: `./server <options>`

available server options:

* -d: specify working directory
* -p: server listen port

Client: `./client <options>`

available client options:

* -i: specify server ip address
* -p: server port
