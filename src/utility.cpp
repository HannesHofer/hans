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

#include "utility.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ios>
#include <fstream>
#include <string.h>
#include <ios>
#include <arpa/inet.h>

using namespace std;
#define RANDOMREAD 4

string Utility::formatIp(const uint32_t &ip)
{
    char buffer[16];
    sprintf(buffer, "%d.%d.%d.%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
    return buffer;
}

uint32_t Utility::rand()
{
    static bool init = false;
    if (!init)
    {
        init = true;
        srand(time(NULL));
    }
    return ::rand();
}

uint64_t Utility::htonll(const uint64_t &value) {
    int num = 42;
    if (*(char *)&num == 42) {
        uint32_t high_part = htonl((uint32_t)(value >> 32));
        uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
        return (((uint64_t)low_part) << 32) | high_part;
    } else {
        return value;
    }
}


/*
    uint32_t randombytes;
    std::ifstream urandom("/dev/urandom", std::ios::in| std::ios::binary);
    urandom.read((char*)&randombytes, RANDOMREAD);
    urandom.close();

    return randombytes;
    */