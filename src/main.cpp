/***************************************************************************
 * This file is part of SigPlugin.                                         *
 * Copyright (c) 2022 V10lator <v10lator@myway.de>                         *
 *                                                                         *
 * This program is free software; you can redistribute it and/or modify    *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation; either version 3 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful,         *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License along *
 * with this program; if not, If not, see <http://www.gnu.org/licenses/>.  *
 ***************************************************************************/

#include <coreinit/title.h>
#include <wups.h>
#include <mocha/mocha.h>

#include <stdint.h>

/**
    Mandatory plugin information.
    If not set correctly, the loader will refuse to use the plugin.
**/
WUPS_PLUGIN_NAME("Signature Patcher");
WUPS_PLUGIN_DESCRIPTION("");
WUPS_PLUGIN_VERSION("v1.1");
WUPS_PLUGIN_AUTHOR("V10lator");
WUPS_PLUGIN_LICENSE("GPL3");

#define VALUE_A 0xE3A00000 // mov r0, #0
#define VALUE_B 0xE12FFF1E // bx lr
#define VALUE_C 0x20004770 // mov r0, #0; bx lr
#define VALUE_D 0x20002000 // mov r0, #0; mov r0, #0

INITIALIZE_PLUGIN()
{
        // Patch under Wii U menu only
        if((OSGetTitleID() & 0xFFFFFFFFFFFFF0FF) != 0x0005001010040000)
                return;

        if(Mocha_InitLibrary() != MOCHA_RESULT_SUCCESS)
                return;

        // patch cached cert check
        Mocha_IOSUKernelWrite32(0x05054D6C, VALUE_A);
        Mocha_IOSUKernelWrite32(0x05054D70, VALUE_B);

        // patch cert verification
        Mocha_IOSUKernelWrite32(0x05052A90, VALUE_A);
        Mocha_IOSUKernelWrite32(0x05052A94, VALUE_B);

        // patch MCP authentication check
        Mocha_IOSUKernelWrite32(0x05014CAC, VALUE_C);

        // patch IOSC_VerifyPubkeySign to always succeed
        Mocha_IOSUKernelWrite32(0x05052C44, VALUE_A);
        Mocha_IOSUKernelWrite32(0x05052C48, VALUE_B);

        // patch OS launch sig check
        Mocha_IOSUKernelWrite32(0x0500A818, VALUE_D);

        Mocha_DeInitLibrary();
}
