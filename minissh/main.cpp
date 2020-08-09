//
//  main.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdio.h>          /* stderr, stdout */
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>         /* opendir, etc. */
#include "Client.h"
#include "Connection.h"

#include "SshAuth.h"
#include "KeyFile.h"

#include "TestRandom.h"
#include "TestUtils.h"
#include "TestNetwork.h"

class KeyHelper
{
private:
    std::vector<std::shared_ptr<minissh::Files::Format::IKeyFile>> _knownKeys;
public:
    void AddDirectory(const std::string& dir, bool wantPrivate)
    {
        DIR *d = opendir(dir.c_str());
        if (!d)
            return;
        dirent *entry;
        std::string fulldir = dir;
        if (fulldir[fulldir.length() - 1] != '/')
            fulldir.append("/");
        while ((entry = readdir(d)) != nullptr)
            if (entry->d_type == DT_REG)
                AddFile(fulldir + entry->d_name, wantPrivate);
        closedir(d);
    }
    
    void AddFile(const std::string& filename, bool wantPrivate)
    {
        FILE *f = fopen(filename.c_str(), "rb");
        fseek(f, 0, SEEK_END);
        int length = ftell(f);
        fseek(f, 0, SEEK_SET);
        minissh::Byte *buf = new minissh::Byte[length];
        fread(buf, 1, length, f);
        fclose(f);
        minissh::Types::Blob blob(buf, length);
        delete[] buf;
        std::shared_ptr<minissh::Files::Format::IKeyFile> file;
        try {
            file = minissh::Files::Format::LoadKeys(blob);
        }
        catch (std::exception) {
            // Any exception indicates file was not a known format
        }
        if (file && wantPrivate) {
            try {
                file->SavePrivate(minissh::Files::Format::FileType::DER);
            }
            catch (std::exception) {
                // If we get here, no private key
                file = nullptr;
            }
        }
        if (file)
            _knownKeys.push_back(file);
    }
    
    int Count(void) const
    {
        return (int)_knownKeys.size();
    }
    
    std::shared_ptr<minissh::Files::Format::IKeyFile> GetKey(int i) const
    {
        return _knownKeys.at(i);
    }
};

class TestAuthentication : public minissh::Client::IAuthenticator
{
private:
    bool _passwordAcceptable;
    int _triedKeys = -1;
    std::string _username;
    
public:
    KeyHelper keys;
    
    void Banner(Replier& replier, const std::string& message, const std::string& languageTag) override
    {
        printf("BANNER: %s\n", message.c_str());
    }
    
    void Query(Replier& replier, const std::optional<std::vector<std::string>>& acceptedModes, bool partiallyAccepted) override
    {
        if (!acceptedModes) {
            // Get username on first run
            char *username = NULL;
            size_t linecap = 0;
            printf("Username: ");
            ssize_t linelen = getline(&username, &linecap, stdin);
            username[linelen - 1] = '\0';    // Remove newline
            _username = username;
            // If acceptedModes isn't provided, it means we're requesting login at first. Do same trick as OpenSSH, request
            // "none" and that will either log us in (unlikely) or report actual accepted modes
            replier.SendNone(_username);
            return;
        }
        if (_triedKeys == -1) {
            _passwordAcceptable = std::find(acceptedModes->begin(), acceptedModes->end(), "password") != acceptedModes->end();
            if (std::find(acceptedModes->begin(), acceptedModes->end(), "publickey") != acceptedModes->end()) {
                _triedKeys = 0;
            } else {
                _triedKeys = keys.Count();
            }
        } else {
            // If it's not the first run, a key failed or the user mis-entered their password
            if (_triedKeys < keys.Count())
                _triedKeys++;
        }
        // Do things
        if (_triedKeys < keys.Count()) {
            replier.SendPublicKey(_username, keys.GetKey(_triedKeys));
        } else {
            if (_passwordAcceptable) {
                char *password = getpass("Password: ");
                replier.SendPassword(_username, password);
            } else {
                throw std::runtime_error("No acceptable authentication mechanisms");
            }
        }
    }
    
    void NeedChangePassword(Replier& replier, const std::string& prompt, const std::string& languageTag) override
    {
        printf("Server says we need to change password (%s)\n", prompt.c_str());
    }
    
    void AcceptablePublicKey(Replier& replier, const std::string& keyAlgorithm, minissh::Types::Blob publicKey) override
    {
        // Technically, we should use publicKey parameter to find the right key from the key set
        replier.UsePrivateKey(_username, keys.GetKey(_triedKeys));
    }
};

class Session : public minissh::Core::Connection::Connection::AChannel
{
public:
    Session(minissh::Core::Connection::Connection& owner)
    :minissh::Core::Connection::Connection::AChannel(owner)
    {
        _shell = false;
    }
    
    OpenChannelInfo OpenInfo(OpenChannelParameters& parameters) override
    {
        return {std::nullopt, "session"};
    }
    
    void Opened(minissh::Types::Blob data) override
    {
        minissh::Types::Blob parameters;
        minissh::Types::Writer writer(parameters);
        writer.WriteString("vt100");
        writer.Write(minissh::UInt32(80));
        writer.Write(minissh::UInt32(24));
        writer.Write(minissh::UInt32(640));
        writer.Write(minissh::UInt32(480));
        char terminalModes[] = {0};
        writer.WriteString(std::string(terminalModes, sizeof(terminalModes)));
        Request("pty-req", true, parameters);
    }
    
    void OpenFailed(minissh::UInt32 reason, const std::string& message, const std::string& languageTag) override
    {
        printf("Failed to create session: %i: %s\n", reason, message.c_str());
    }
    
    void ReceivedRequestResponse(bool success) override
    {
        if (!success) {
            printf("Failed to open TTY\n");
            return;
        }
        if (!_shell) {
            _shell = true;
            Request("shell", false, std::nullopt);
        }
    }
    
    void ReceivedClose(void) override
    {
        printf("Session closed\n");
    }
    
    void ReceivedData(minissh::Types::Blob data) override
    {
        for (int i = 0; i < data.Length(); i++)
            printf("%c", data.Value()[i]);
        fflush(stdout);
    }
    
    void ReceivedExtendedData(minissh::UInt32 type, minissh::Types::Blob data) override
    {
        for (int i = 0; i < data.Length(); i++)
            printf("%c", data.Value()[i]);
        fflush(stdout);
    }
    
    void Send(const char *keystrokes, minissh::UInt32 length)
    {
        AChannel::Send(minissh::Types::Blob((minissh::Byte*)keystrokes, length));
    }
    
private:
    bool _shell;
};

class Stdin : public BaseFD
{
public:
    Stdin(Session *session)
    :_session(session)
    {
        _fd = fileno(stdin);
    }
    
protected:
    void OnEvent(void) override
    {
        char c[100];
        int amount = (int)read(_fd, c, 100);
        _session->Send(c, amount);
    }
    
private:
    Session *_session;
};

int main(int argc, const char * argv[])
{
    if (argc < 2) {
        printf("usage: %s <host> [<port>] [<key directory>]\n", argv[0]);
        return -1;
    }
    uint16_t portnum = 22;
    if (argc >= 3)
        portnum = atoi(argv[2]);
    TestAuthentication testAuth;
    if (argc >= 4) {
        testAuth.keys.AddDirectory(argv[3], true);
        printf("Loaded %i private keys from %s\n", testAuth.keys.Count(), argv[3]);
    }
    Socket *test = new Socket(argv[1], portnum);
    TestRandom randomiser;
    minissh::Core::Client client(randomiser);
    test->transport = &client;
    ConfigureSSH(test->transport->configuration);
    test->transport->SetDelegate(test);
    minissh::Client::AuthService *auth = new minissh::Client::AuthService(client, client.DefaultEnabler());
    auth->SetAuthenticator(&testAuth);
    minissh::Core::Connection::Client connection(client, auth->AuthEnabler());
    std::shared_ptr<Session> session = std::make_shared<Session>(connection);
    connection.OpenChannel(session);
    Stdin stdinRead(session.get());
    test->transport->Start();
    BaseFD::Run();
    return 0;
}
