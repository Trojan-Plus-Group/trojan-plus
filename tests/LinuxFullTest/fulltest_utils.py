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
import sys, datetime

def is_linux_system():
    return sys.platform == "linux" or sys.platform == "linux2"

def is_macos_system():
    return sys.platform == "darwin"

def is_windows_system():
    return sys.platform == "win32"

former_print_time_log_datatime = None
def print_time_log(log = None, end = '\n'):
    current_datetime = datetime.datetime.now()
    time_str = current_datetime.strftime('%H:%M:%S')

    global former_print_time_log_datatime
    if former_print_time_log_datatime :
        time_str = time_str + ' E' + str(current_datetime - former_print_time_log_datatime)

    print('[' + time_str + '] ' + str(log if log else ''), end = end)
    former_print_time_log_datatime = current_datetime
