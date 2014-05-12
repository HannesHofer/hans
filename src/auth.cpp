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

#include "auth.h"
#include "utility.h"

#include <arpa/inet.h>

Auth::Auth(const char *passphrase)
{
    this->passphrase = passphrase;

    //TODO evalute this for better keystreching
    crypto_hash_sha256(this->encryptionkey, (const unsigned char*)passphrase, this->passphrase.length());
    for (int i=0;i<65535;++i)
        crypto_hash_sha256(this->encryptionkey, (const unsigned char*)this->encryptionkey, crypto_hash_sha256_BYTES);
}

Auth::Response Auth::getResponse(const Challenge &challenge) const
{
    Response response;

    int inputlen = passphrase.length() + challenge.size();
    unsigned char input[inputlen];
    memcpy(input, passphrase.c_str(), passphrase.length());
    memcpy(input + passphrase.length(), &challenge[0], challenge.size());

    crypto_hash_sha256(&response.data[0], input, inputlen);

    return response;
}

Auth::Challenge Auth::generateChallenge(int length) const
{
    Challenge challenge;
    challenge.resize(length);

    for (int i = 0; i < length; i++)
        challenge[i] = Utility::rand();

    return challenge;
}
