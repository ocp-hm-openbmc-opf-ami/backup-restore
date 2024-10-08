

/* ****************************************************************
 *
 * Backup and Restore
 * backup_service.cpp
 *
 * @brief dbus service for Backup and Restore
 *
 * Author: Lucas Panayioto lucasp@ami.com
 *
 *****************************************************************/
#include "backup_service.hpp"

//Dbus
#include "config.h"
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Backup/BackupRestore/server.hpp>


#include <getopt.h>

#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>


//Definitions
#define BACKUPCONF_FILE         "/var/backups/backupconf.json"
#define BACKUP_FOLDER           "/tmp/backup"
#define RESTORE_FOLDER          "/tmp/restore"

#define SMTP                    "S"
#define VIRTUALMEDIA            "V"
#define NETWORK                 "N"


// D-Bus root for backup restore
constexpr auto backupRestoreRoot = "/xyz/openbmc_project/Backup";

using::phosphor::logging::elog;
using::phosphor::logging::entry;
using::phosphor::logging::level;
using::phosphor::logging::log;
using::phosphor::logging::report;
using::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using IfcBase = sdbusplus::xyz::openbmc_project::Backup::server::BackupRestore;
using json = nlohmann::json;

namespace fs = std::filesystem;


class BackupImp: IfcBase
{
private:

    void restartService(const std::string& serviceName)
    {
        std::string restart_command = "/bin/systemctl restart " + serviceName;
        int ret = std::system(restart_command.c_str());
        if (ret == -1) {
            std::cerr << "Error in restarting service: " << serviceName << std::endl;
        } else {
            std::cout << "Restarted the service: " << serviceName << std::endl;
        }
    }



public:

/* Define all of the basic class operations:
 *     Not allowed:
 *         - Default constructor to avoid nullptrs.
 *         - Copy operations due to internal unique_ptr.
 *         - Move operations due to 'this' being registered as the
 *           'context' with sdbus.
 *     Allowed:
 *         - Destructor.
 */
BackupImp() = delete;
BackupImp(const BackupImp &) = delete;
BackupImp & operator = (const BackupImp &) = delete;
BackupImp(BackupImp &&) = delete;
BackupImp & operator = (BackupImp &&) = delete;

/** @brief Constructor to put object onto bus at a dbus path.
 *  @param[in] bus - Bus to attach to.
 *  @param[in] path - Path to attach at.
 */
BackupImp(sdbusplus::bus_t & bus, const char * path): IfcBase(bus, path)
{
    Initialize_Key();
    //setPropertyByName(std::string{"backupFlags"},std::string{"N"});
}


/** Method: Create Backup file
 *  @brief Implementation Create Backup file
 *  @param[in] fileName - name of backup file
 */
std::string createBackup(std::string fileName) override
{
    bool backupExist = false;

    fs::current_path(fs::temp_directory_path());

    // clean backup folder
    if (fs::exists("backup"))
        fs::remove_all("backup");

    fs::create_directories("backup/" + fileName);
    std::ifstream fpConf;

    fpConf.open(BACKUPCONF_FILE);

    json jfConf = json::parse(fpConf);

    std::vector < std::string > confFolders;
    std::vector < std::string > confFiles;

    // Read the backupconf
    for (auto & jfBackupFlags: jfConf.items())
    {
        //Check the flags
        if (IfcBase::backupFlags().find(jfBackupFlags.key()) != std::string::npos)
        {
            for (auto & jfFlagFiles: jfBackupFlags.value().items())
            {
                // Get the file(s) and folder of the flag
                if (jfFlagFiles.key() == "file")
                {
                    confFiles = jfFlagFiles.value();
                }
                else if (jfFlagFiles.key() == "folder")
                {
                    confFolders = jfFlagFiles.value();
                }
            }

            for (auto tempFolder: confFolders)
            {
                for (auto tempFile: confFiles)
                {
                    if (fs::exists(tempFolder + "/" + tempFile))
                    {
                        fs::create_directories("backup/" + fileName + tempFolder);
                        fs::copy_file(tempFolder + "/" + tempFile, "backup/" + fileName + tempFolder + "/" + tempFile,
                             
                            fs::copy_options::overwrite_existing);
                        backupExist = true;
                    }
                }
            }
        }
    }

    fpConf.close();

    if (!backupExist)
    {
        return std::string
        {
            "/dev/null"
        };
    }

    //zip the file
    executeCmd("/bin/tar", "-cf", ("/tmp/backup/" + fileName + "_dcrpt.tar").c_str(), ("/tmp/backup/" + fileName).c_str());

    // Encrypt the tar file
    std::string encryptedFilePath = encryptFile(fileName);
    return encryptedFilePath;
}


/** Method: Restore Backup file
 *  @brief Implementation Restore Backup file
 *  @param[in] fileName - name of backup file
 */
bool restoreBackup(std::string fileName) override
{
    std::vector < std::string > confFolders;
    std::vector < std::string > confFiles;
    std::vector < std::string > services;

    std::ifstream fpConf;
    fs::current_path(fs::temp_directory_path());
    fpConf.open(BACKUPCONF_FILE);
    json jfConf = json::parse(fpConf);

    //check if backup folder exists
    fs::path encryptedFilePath = "/tmp/restore/" + fileName + ".tar";
    if (!fs::exists(encryptedFilePath))
    {
        if (fs::exists("restore"))
            fs::remove_all("restore");

        return false;
    }

    if (!decryptFile(fileName))
    {
        if (fs::exists("restore"))
            fs::remove_all("restore");

        return false;
    }

    //unzip the file with option overwrite files
    executeCmd("/bin/tar", "-xf", ("/tmp/restore/" + fileName + "_dcrpt.tar").c_str(), "-C", "/tmp/restore/");

    // Check what backup files exist for restoring
    // Read the backupconf
    for (auto & jfBackupFlags: jfConf.items())
    {

        //Check the flags
        if ((IfcBase::backupFlags().find(jfBackupFlags.key()) != std::string::npos) ||
             (IfcBase::backupFlags().empty() == true))
        {
            
            for (auto & jfFlagFiles: jfBackupFlags.value().items())
            {
                // Get the file(s) and folder of the flag
                if (jfFlagFiles.key() == "file")
                {
                    confFiles = jfFlagFiles.value();
                }
                else if (jfFlagFiles.key() == "folder")
                {
                    confFolders = jfFlagFiles.value();
                }
                else if(jfFlagFiles.key() == "service")
                {
                    services =  jfFlagFiles.value();
                }
            }

            for (auto tempFolder: confFolders)
            {
                for (auto tempFile: confFiles)
                {
                    if (fs::exists(tempFolder + "/" + tempFile))
                    {
                        //Restoring files
                        fs::path restorefile(("/tmp/restore/tmp/backup/" + fileName + tempFolder + "/" + tempFile).c_str());

                        if (fs::exists(restorefile))
                        {
                            // trying to copy files
                            try 
                            {
                                fs::path confStream((tempFolder + "/" + tempFile).c_str());

                                // remove the read permission from others if password is being written.
                                // nslcd forces this behaviour.
                                auto permission =
                                     fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read;

                                fs::permissions((tempFolder + "/" + tempFile).c_str(), permission);
                                fs::copy_file(restorefile, confStream, fs::copy_options::overwrite_existing);
                            }

                            catch (const std::exception & e)
                            {
                                log < level::ERR > (e.what());
                                elog < InternalFailure > ();
                            }
                        } //if file for restoring exists
                    } //if temp folder exists
                } //for confFile
            } //for confFolder
            for (auto tempServices: services)
            {
                restartService(tempServices);
            }
        }
    }

    fpConf.close();
    if (fs::exists("restore"))
            fs::remove_all("restore");

    return true;
}


/** Property: backup Flags
 *  @brief
 *  @param[in] value - new value of the property
 */
std::string backupFlags(std::string value) override
{
    std::string val;

    try 
    {
        if (value == IfcBase::backupFlags())
        {
            return value;
        }

        val = IfcBase::backupFlags(value);
    }

    catch (const std::exception & e)
    {
        log < level::ERR > (e.what());
        elog < InternalFailure > ();
    }

    return val;
}


};


int main(int argc, char * *argv)
{

    if (0)
    {
        argc = argc;
        argv = argv;
    }
    CheckAndWriteBackupKey(aesKeyFile ,GET_ENCRYPT_KEY);
    CheckAndWriteBackupKey(aesIVFile ,GET_INITIAL_VECTOR);
    auto bus = sdbusplus::bus::new_default();

    // Claim the bus now
    bus.request_name("xyz.openbmc_project.Backup");

    sdbusplus::server::manager_t objManager(bus, backupRestoreRoot);

    BackupImp backupManager(bus, backupRestoreRoot);

    // Wait for client request
    bus.process_loop();

    return - 1;
}


