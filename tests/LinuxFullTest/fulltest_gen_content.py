'''
 This file is part of the Trojan Plus project.
 Trojan is an unidentifiable mechanism that helps you bypass GFW.
 Trojan Plus is derived from original trojan project and writing 
 for more experimental features.
 Copyright (C) 2020 The Trojan Plus Group Authors.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import random, os, shutil
import fulltest_udp_proto

def get_random_string(length):
    RANDOM_STRING = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    arr = [None] * length
    for i in range(0, length) :
        arr[i] =  RANDOM_STRING[random.randint(0, len(RANDOM_STRING) - 1)]
    return "".join(arr)

def gen_files(parent_dir, files_count, file_size):
    if file_size / fulltest_udp_proto.SEND_PACKET_LENGTH >= 256:
        raise Exception(" gen files is too large! we need remain 1 byte for index of udp")

    if os.path.exists(parent_dir) :
        shutil.rmtree(parent_dir)

    os.mkdir(parent_dir)

    files_index=[]
    for _ in range(0, files_count) : 
        while True:
            name = (get_random_string(10) + '.txt')
            if not (name in files_index):
                files_index.append(name)
                break

        with open(parent_dir + "/" + name, "w") as fd:
            fd.write(get_random_string(file_size))

    with open(parent_dir + "/index.html", "w") as fd:
        first_line = True
        for file in files_index:
            fd.write(('' if first_line else '\n') + file)
            first_line = False
        
if __name__ == '__main__':
    gen_files('html', 10, 8192 * 10)
