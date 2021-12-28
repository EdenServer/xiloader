/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

This file is part of DarkStar-server source code.

===========================================================================
*/

#include "network.h"
#include "functions.h"

/* Externals */
extern std::string g_ServerAddress;
extern std::string g_Email;
extern std::string g_Discord;
extern std::string g_Username;
extern std::string g_Password;
extern std::string g_ServerPort;
extern std::string g_Hostname;
extern unsigned char g_SessionHash[16];
extern char* g_CharacterList;
extern bool g_IsRunning;

namespace xiloader
{
    /**
     * @brief Creates a connection on the given port.
     *
     * @param sock      The datasocket object to store information within.
     * @param port      The port to create the connection on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateConnection(datasocket* sock, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        /* Attempt to get the server information. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(g_ServerAddress.c_str(), port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
            return 0;
        }

        /* Determine which address is valid to connect.. */
        for (auto ptr = addr; ptr != NULL; ptr->ai_next)
        {
            /* Attempt to create the socket.. */
            sock->s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (sock->s == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Failed to create socket.");

                freeaddrinfo(addr);
                return 0;
            }

            /* Attempt to connect to the server.. */
            if (connect(sock->s, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to connect to server!");

                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return 0;
            }

            xiloader::console::output(xiloader::color::info, "Connected to server!");
            break;
        }

        std::string localAddress = "";

        /* Attempt to locate the client address.. */
        char hostname[1024] = { 0 };
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            PHOSTENT hostent = NULL;
            if ((hostent = gethostbyname(hostname)) != NULL)
                localAddress = inet_ntoa(*(struct in_addr*)*hostent->h_addr_list);
        }

        sock->LocalAddress = inet_addr(localAddress.c_str());
        sock->ServerAddress = inet_addr(g_ServerAddress.c_str());

        return 1;
    }

    /**
     * @brief Creates a listening server on the given port and protocol.
     *
     * @param sock      The socket object to bind to.
     * @param protocol  The protocol to use on the new listening socket.
     * @param port      The port to bind to listen on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateListenServer(SOCKET* sock, int protocol, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = protocol;
        hints.ai_flags = AI_PASSIVE;

        /* Attempt to resolve the local address.. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(NULL, port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain local address information.");
            return false;
        }

        /* Create the listening socket.. */
        *sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (*sock == INVALID_SOCKET)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create listening socket.");

            freeaddrinfo(addr);
            return false;
        }

        /* Bind to the local address.. */
        if (bind(*sock, addr->ai_addr, (int)addr->ai_addrlen) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to bind to listening socket.");

            freeaddrinfo(addr);
            closesocket(*sock);
            *sock = INVALID_SOCKET;
            return false;
        }

        freeaddrinfo(addr);

        /* Attempt to listen for clients if we are using TCP.. */
        if (protocol == IPPROTO_TCP)
        {
            if (listen(*sock, SOMAXCONN) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to listen for connections.");

                closesocket(*sock);
                *sock = INVALID_SOCKET;
                return false;
            }
        }

        return true;
    }


    /**
     * @brief Resolves the given hostname to its long ip format.
     *
     * @param host      The host name to resolve.
     * @param lpOutput  Pointer to a ULONG to store the result.
     *
     * @return True on success, false otherwise.
     */
    bool network::ResolveHostname(const char* host, PULONG lpOutput)
    {
        struct addrinfo hints, *info = 0;
        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(host, "1000", &hints, &info))
            return false;

        *lpOutput = ((struct sockaddr_in*)info->ai_addr)->sin_addr.S_un.S_addr;

        freeaddrinfo(info);
        return true;
    }

    void network::MaskPassword(std::string* mask)
    {
        /* Read in each char and instead of displaying it. display a "*" */
        char ch;
        while ((ch = static_cast<char>(_getch())) != '\r')
        {
            if (ch == '\0')
                continue;
            else if (ch == '\b')
            {
                if (mask->size())
                {
                    mask->pop_back();
                    std::cout << "\b \b";
                }
            }
            else
            {
                mask->push_back(ch);
                std::cout << '*';
            }
        }
        std::cout << std::endl;
    }

    /**
     * @brief Verifies the players login information; also handles creating new accounts.
     *
     * @param sock      The datasocket object with the connection socket.
     *
     * @return True on success, false otherwise.
     */
    bool network::VerifyAccount(datasocket* sock)
    {
        static bool bFirstLogin = true;

        char recvBuffer[32768] = { 0 };
        char sendBuffer[1024] = { 0 };
        std::string registrationCode;

        /* Create connection if required.. */
        if (sock->s == NULL || sock->s == INVALID_SOCKET)
        {
            if (!xiloader::network::CreateConnection(sock, "54231"))
                return false;
        }

        /* Determine if we should auto-login.. */
        bool bUseAutoLogin = !g_Username.empty() && !g_Password.empty() && bFirstLogin;
        if (bUseAutoLogin)
            xiloader::console::output(xiloader::color::lightgreen, "Autologin activated!");

        bool doLogin = true;

        if (!bUseAutoLogin)
        {
            xiloader::console::output(xiloader::color::grey, "==========================================================");
            xiloader::console::output(xiloader::color::lightgreen, "What would you like to do?");
            xiloader::console::output(xiloader::color::lightcyan, "   1.) Login");
            xiloader::console::output(xiloader::color::white, "   2.) Create Account (requires registration code)");
            xiloader::console::output(xiloader::color::grey, "   3.) Quit");
            xiloader::console::output(xiloader::color::grey, "==========================================================");
            printf("\nEnter a selection: ");

            std::string input;
            std::cin >> input;
            std::cout << std::endl;

            /* User wants to log into an existing account.. */
            if (input == "1")
            {
                xiloader::console::output("Please enter your login information. Press CTRL + c to quit.");
                std::cout << "\nUsername: ";
                std::cin >> g_Username;
                std::cout << "Password: ";
                g_Password.clear();
                MaskPassword(&g_Password);
                std::cin.ignore();
            }
            /* User wants to create a new account.. */
            else if (input == "2")
            {
                console::output(color::lightyelllow, "Please enter the required information to create an account.");
                console::output(color::lightyelllow, "To obtain a registration code visit Eden's Discord channel.");

                std::cout << "Registration Code                : ";
                std::cin >> registrationCode;

            retry_email_2:
                std::cout << "E-mail (used for password reset) : ";
                std::cin >> g_Email;
                std::cout << "Repeat E-mail                    : ";
                std::cin >> input;

                if (input != g_Email || g_Email.length() < 3 || g_Email.length() > 63)
                {
                    console::output(color::error, "E-mails mismatch, too short, or too long!  Please try again.");
                    g_Email.clear();
                    input.clear();
                    goto retry_email_2;
                }

            retry_username_2:
                std::cout << "Username (3-31 characters)       : ";
                std::cin >> g_Username;

                if (g_Username.length() < 3 || g_Username.length() > 31)
                {
                    console::output(color::error, "Username too short or too long!  Please try again.");
                    g_Username.clear();
                    goto retry_username_2;
                }

            retry_password_2:
                g_Password.clear();
                input.clear();

                std::cout << "Password (6-31 characters)       : ";
                MaskPassword(&g_Password);
                std::cout << "Repeat Password                  : ";
                MaskPassword(&input);

                if (input != g_Password || g_Password.length() < 6 || g_Password.length() > 31)
                {
                    console::output(color::error, "Passwords mismatch, too short, or too long!  Please try again.");
                    goto retry_password_2;
                }

            retry_discord_2:
                g_Discord.clear();
                std::cout << "Optional Discord handle, example Eden#1234\n";
                std::cout << "(6-31 characters, ENTER for none): ";
                std::cin.ignore();
                getline(std::cin, g_Discord);

                if (g_Discord.length() != 0 && (g_Discord.length() < 6 || g_Discord.length() > 31))
                {
                    console::output(color::error, "Discord handle too short or too long!  Please try again.");
                    goto retry_discord_2;
                }

                doLogin = false;
            }
            else if (input == "3")
            {
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                exit(0);
            }

            std::cout << std::endl;
        }
        else
        {
            /* User has auto-login enabled.. */
            bFirstLogin = false;
        }

        sendBuffer[0] = 1;
        send(sock->s, sendBuffer, 1, 0);

        unsigned int expectedLength = 0;
        recv(sock->s, (char*)&expectedLength, 4, 0);

        int bytesRead = 0;
        int received = 0;
        do
        {
            received = recv(sock->s, recvBuffer + bytesRead, expectedLength - bytesRead, 0);
            bytesRead += received;
        } while (expectedLength > bytesRead && received != 0);

        std::string uniqueKey(recvBuffer + bytesRead - 8, recvBuffer + bytesRead);

        memset(sendBuffer, 0, 1024);
        memset(recvBuffer, 0, 32768);

        if (doLogin)
        {
            sendBuffer[0xFF] = 0x10; // LOGIN
        }
        else
        {
            sendBuffer[0xFF] = 0x20; // LOGIN_CREATE
        }

        /* Copy username and password into buffer.. */
        memcpy(sendBuffer + 0x0, g_Username.c_str(), 32);
        memcpy(sendBuffer + 0x20, g_Discord.c_str(), 32);
        memcpy(sendBuffer + 0x40, g_Password.c_str(), 32);
        memcpy(sendBuffer + 0x80, g_Email.c_str(), 64);
        memcpy(sendBuffer + 0xC0, xiloader::functions::getMACAddress().c_str(), 17);
        memcpy(sendBuffer + 0xE0, uniqueKey.c_str(), 8);
        memcpy(sendBuffer + 0xE8, registrationCode.c_str(), 7);
        memcpy(sendBuffer + 0xEF, g_Hostname.c_str(), 15);

        memcpy(sendBuffer + 0xD7, "1", 1);

        /* Simple bit flipping to mask the values in-transit, and simple crc for integrity */
        for (int index = 0; index < 0x100; ++index)
        {
            if (sendBuffer[index] != 0x00 && sendBuffer[index] != 0xFF)
            {
                sendBuffer[index] ^= 0xFF;
                sendBuffer[0x100 + (index % 4)] ^= sendBuffer[index];
            }
        }

        /* Send info to server and obtain response.. */
        send(sock->s, sendBuffer, 0x104, 0);
        recv(sock->s, recvBuffer, 0x15, 0);

        bool result = false;

        /* Handle the obtained result.. */
        switch (recvBuffer[0])
        {
        case 0x0001: // Success (Login)
            xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", g_Username.c_str());
            sock->AccountId = *(UINT32*)(recvBuffer + 0x01);
            memcpy(g_SessionHash, (UCHAR*)(recvBuffer + 0x05), 16);
            result = true;
            break;
        case 0x0002: // Error (Login)
            xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");
            break;
        case 0x0003: // Success (Create Account)
            xiloader::console::output(xiloader::color::success, "Account successfully created!");
            sock->AccountId = *(UINT32*)(recvBuffer + 0x01);
            memcpy(g_SessionHash, (UCHAR*)(recvBuffer + 0x05), 16);
            result = true;
            break;
        case 0x0004: // Error (Create Account)
            xiloader::console::output(xiloader::color::error, "Failed to create the new account. Username already taken.");
            break;
        case 0x0014: // Error (Create Account Taken)
            console::output(color::error, "Username \"%s\" already taken.", g_Username.c_str());
            break;
        case 0x0024: // Error (Create Account Syntax)
            console::output(color::error, "Invalid e-mail format \"%s\".", g_Email.c_str());
            break;
        case 0x0034: // Error (Create Account Code)
            console::output(color::error, "Registration code \"%s\" is either invalid or has expired.", registrationCode.c_str());
            break;
        case 0x0044: // Error (Create Account Lock-out)
            console::output(color::warning, "Warning, account creation is in lock-out period.  Try again shortly.");
            break;
        case 0x0005: // Wait (Session Active)
            console::output(color::warning, "Character logged in. Please wait a few minutes and try again.");
            break;
        case 0x0006: // Invalid (Login)
            console::output(color::warning, "Invalid username or password.");
            break;
        case 0x0007: // Too many connections.
            console::output(color::warning, "Too many connections from the same location.");
            break;
        default:
            console::output(color::error, "Unexpected server response: %d", recvBuffer[0]);
            break;
        }

        closesocket(sock->s);
        sock->s = INVALID_SOCKET;

        if (!result)
        {
            std::cout << "Press the ENTER key to close and retry...";
            getline(std::cin, registrationCode);
            exit(0);
        }

        return result;
    }

    bool socket_connected(SOCKET sock)
    {
        char buf;
        int err = recv(sock, &buf, 1, MSG_PEEK);
        if (err == SOCKET_ERROR)
        {
            if (WSAGetLastError() != WSAEWOULDBLOCK)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief Data communication between the local client and the game server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::FFXiDataComm(LPVOID lpParam)
    {
        auto sock = (xiloader::datasocket*)lpParam;

        int sendSize = 0;
        char recvBuffer[4096] = { 0 };
        char sendBuffer[4096] = { 0 };

        while (g_IsRunning)
        {
            /* Attempt to receive the incoming data.. */
            struct sockaddr_in client;
            unsigned int socksize = sizeof(client);
            if (recvfrom(sock->s, recvBuffer, sizeof(recvBuffer), 0, (struct sockaddr*)&client, (int*)&socksize) <= 0)
                continue;

            switch (recvBuffer[0])
            {
            case 0x0001:
                sendBuffer[0] = 0xA1u;
                memcpy(sendBuffer + 0x01, &sock->AccountId, 4);
                memcpy(sendBuffer + 0x05, &sock->ServerAddress, 4);
                memcpy(sendBuffer + 0x09, &g_SessionHash, 16);
                xiloader::console::output(xiloader::color::warning, "Sending account id..");
                sendSize = 25;
                break;

            case 0x0002:
            case 0x0015:
                memcpy(sendBuffer, (char*)"\xA2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58\xE0\x5D\xAD\x00\x00\x00\x00", 25);
                xiloader::console::output(xiloader::color::warning, "Sending key..");
                sendSize = 25;
                break;

            case 0x0003:
            case 0x0004:
                xiloader::console::output(xiloader::color::warning, "Receiving character list..");
                for (auto x = 0; x < recvBuffer[1]; x++) // 1 = size/length/character count
                {
                    g_CharacterList[0x00 + (x * 0x68)] = 1;
                    g_CharacterList[0x02 + (x * 0x68)] = 1;
                    g_CharacterList[0x10 + (x * 0x68)] = (char)x;
                    g_CharacterList[0x11 + (x * 0x68)] = 0x80u;
                    g_CharacterList[0x18 + (x * 0x68)] = 0x20;
                    g_CharacterList[0x28 + (x * 0x68)] = 0x20;

                    memcpy(g_CharacterList + 0x04 + (x * 0x68), recvBuffer + 0x10 * (x + 1) + 0x04, 4); // Character Id
                    memcpy(g_CharacterList + 0x08 + (x * 0x68), recvBuffer + 0x10 * (x + 1), 4); // Content Id
                }
                sendSize = 0;
                break;

            case 0x0005:
                sendBuffer[0] = 0xA5u; // Heartbeat response
                sendSize = 1;
                break;
            }

            if (sendSize == 0)
                continue;

            /* Send the response buffer to the server.. */
            auto result = sendto(sock->s, sendBuffer, sendSize, 0, (struct sockaddr*)&client, socksize);
            if (sendSize == 72 || result == SOCKET_ERROR || sendSize == -1)
            {
                if (!socket_connected(sock->s)) {
                    console::output("Data socket disconnected...attempting to reconnect.");
                    if (!network::CreateConnection((datasocket*)lpParam, "54230"))
                    {
                        shutdown(sock->s, SD_SEND);
                        closesocket(sock->s);
                        sock->s = INVALID_SOCKET;

                        xiloader::console::output("Server connection done; disconnecting!");
                        return 0;
                    }
                }
            }

            sendSize = 0;
            Sleep(100);
        }

        return 0;
    }

    /**
     * @brief Data communication between the local client and the lobby server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolDataComm(LPVOID lpParam)
    {
        SOCKET client = *(SOCKET*)lpParam;
        unsigned char recvBuffer[1024] = { 0 };
        int result = 0, x = 0;
        time_t t = 0;
        bool bIsNewChar = false;

        do
        {
            /* Attempt to receive incoming data.. */
            result = recv(client, (char*)recvBuffer, sizeof(recvBuffer), 0);
            if (result <= 0)
            {
                xiloader::console::output(xiloader::color::error, "Client recv failed: %d", WSAGetLastError());
                break;
            }

            char temp = recvBuffer[0x04];
            memset(recvBuffer, 0x00, 32);

            switch (x)
            {
            case 0:
                recvBuffer[0] = 0x81;
                t = time(NULL);
                memcpy(recvBuffer + 0x14, &t, 4);
                result = 24;
                break;

            case 1:
                if (temp != 0x28)
                    bIsNewChar = true;
                recvBuffer[0x00] = 0x28;
                recvBuffer[0x04] = 0x20;
                recvBuffer[0x08] = 0x01;
                recvBuffer[0x0B] = 0x7F;
                result = bIsNewChar ? 144 : 24;
                if (bIsNewChar) bIsNewChar = false;
                break;
            }

            /* Echo back the buffer to the server.. */
            if (send(client, (char*)recvBuffer, result, 0) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Client send failed: %d", WSAGetLastError());
                break;
            }

            /* Increase the current packet count.. */
            x++;
            if (x == 3)
                break;

        } while (result > 0);

        /* Shutdown the client socket.. */
        if (shutdown(client, SD_SEND) == SOCKET_ERROR)
            xiloader::console::output(xiloader::color::error, "Client shutdown failed: %d", WSAGetLastError());
        closesocket(client);

        return 0;
    }

    /**
     * @brief Starts the data communication between the client and server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::FFXiServer(LPVOID lpParam)
    {
        /* Attempt to create connection to the server.. */
        if (!xiloader::network::CreateConnection((xiloader::datasocket*)lpParam, "54230"))
            return 1;

        /* Attempt to start data communication with the server.. */
        CreateThread(NULL, 0, xiloader::network::FFXiDataComm, lpParam, 0, NULL);
        Sleep(200);

        return 0;
    }

    /**
     * @brief Starts the local listen server to lobby server communications.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolServer(LPVOID lpParam)
    {
        UNREFERENCED_PARAMETER(lpParam);

        SOCKET sock, client;

        /* Attempt to create listening server.. */
        if (!xiloader::network::CreateListenServer(&sock, IPPROTO_TCP, g_ServerPort.c_str()))
            return 1;

        while (g_IsRunning)
        {
            /* Attempt to accept incoming connections.. */
            if ((client = accept(sock, NULL, NULL)) == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Accept failed: %d", WSAGetLastError());

                closesocket(sock);
                return 1;
            }

            /* Start data communication for this client.. */
            CreateThread(NULL, 0, xiloader::network::PolDataComm, &client, 0, NULL);
        }

        closesocket(sock);
        return 0;
    }

}; // namespace xiloader
