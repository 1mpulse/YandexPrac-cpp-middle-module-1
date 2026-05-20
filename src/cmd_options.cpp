#include "cmd_options.h"

#include <iostream>
#include <print>

namespace CryptoGuard {
namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options")
{
    desc_.add_options()
        ("help", "list of available options")
        ("command", po::value<std::string>(), "command: encrypt, decrypt or checksum")
        ("input,i", po::value<std::string>(), "path input file")
        ("output,o", po::value<std::string>(), "path output file")
        ("password,p", po::value<std::string>(), "password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[])
{
    po::variables_map vm;

    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.contains("help"))
    {
        std::cout << desc_ << std::endl;
        return;
    }

    po::notify(vm);

    if (!vm.contains("command"))
    {
        std::print("Argument missing: --command\n");
        return;
    }

    const auto command = vm["command"].as<std::string>();
    const auto commandIt = commandMapping_.find(std::string_view(command));

    if (commandIt == commandMapping_.end())
    {
        std::print("Invalid command: {}\nAvailable commands: encrypt, decrypt, checksum", command);
        return;
    }

    command_ = commandIt->second;

    if (!vm.contains("input"))
    {
        std::print("Argument missing: --input\n");
        return;
    }

    inputFile_ = vm["input"].as<std::string>();

    if (!vm.contains("output"))
    {
        std::print("Argument missing: --output\n");
        return;
    }

    outputFile_ = vm["output"].as<std::string>();

    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT)
    {
        if (!vm.contains("password"))
        {
            std::print("Argument missing: --password (encrypt/decrypt)\n");
            return;
        }

        password_ = vm["password"].as<std::string>();
    }
    else
    {
        password_.clear();
    }
}

}  // namespace CryptoGuard
