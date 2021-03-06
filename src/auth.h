/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2009 Friedrich Schöller <hans@schoeller.se>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef AUTH_H
#define AUTH_H

#include <vector>
#include <string>
#include <string.h>
#include <stdint.h>
#include <nacl/crypto_hash_sha256.h>

class Auth
{
public:
    typedef std::vector<char> Challenge;

    struct Response
    {
        unsigned char data[crypto_hash_sha256_BYTES];
        bool operator==(const Response &other) const { return memcmp(this, &other, sizeof(Response)) == 0; }
    };

    Auth(const char *passphrase);

    Challenge generateChallenge(int length) const;
    Response getResponse(const Challenge &challenge) const;
    unsigned char *getEncryptionKey() {return encryptionkey;}
    int getEncryptionKeyLength() { return crypto_hash_sha256_BYTES; }

protected:
    std::string passphrase;
    std::string challenge;
    unsigned char encryptionkey[crypto_hash_sha256_BYTES];
};

#endif
