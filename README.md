# memoires-decrypt

This cross-platform command-line program decrypts journals encrypted with
[Mémoires 4.0][mem] and later.  The result of decryption is the original
unencrypted journal (which is an SQLite database file).

*Of course, you need the original password to decrypt.*

The program is freely available under the 2-clause BSD license as an
anti-lock in initiative of [Coding Robots][cr], makers of Mémoires.
We support open standards and data portability.


## Installation

To install the program from sources, first install [Go programming language][go].
Then type the following command in Terminal:

	go get github.com/coding-robots/memoires-decrypt

This command will install `memoires-decrypt` into your $GOPATH/bin directory.


## Usage

	memoires-decrypt -p="password" -in="encrypted.memoire" out="decrypted.memoire"

where:

	-in: encrypted journal file
	-out: decrypted SQLite file
	-p: password


[mem]: http://www.codingrobots.com/memoires/
[cr]: http://www.codingrobots.com
[go]: http://golang.org
