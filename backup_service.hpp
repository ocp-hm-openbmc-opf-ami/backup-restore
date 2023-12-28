

/* ****************************************************************
*
* Backup and Restore
* backup_service.hpp
*
* @brief dbus service for Backup and Restore
*
* Author: Lucas Panayioto lucasp@ami.com
*
*****************************************************************/
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>


//Error Logging
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <getopt.h>

#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>

using::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;


template <typename... ArgTypes> std::vector <std::string> executeCmd(const char * path, ArgTypes && ... tArgs)
{
    std::vector <std::string> stdOutput;
    boost::process::ipstream stdOutStream;
    boost::process::child execProg(path, const_cast <char*> (tArgs) ..., 
        boost::process::std_out > stdOutStream);
    std::string stdOutLine;

    while (stdOutStream && std::getline(stdOutStream, stdOutLine) && !stdOutLine.empty())
    {
        stdOutput.emplace_back(stdOutLine);
    }

    execProg.wait();

    int retCode = execProg.exit_code();

    if (retCode)
    {
        phosphor::logging::log <phosphor::logging::level::ERR> ("Command execution failed", 
            phosphor::logging::entry("PATH=%d", path), 
            phosphor::logging::entry("RETURN_CODE:%d", retCode));
        phosphor::logging::elog <InternalFailure> ();

    }

    return stdOutput;
}


