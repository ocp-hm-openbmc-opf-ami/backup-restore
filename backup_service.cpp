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


//Definitions
#define NETWORK_CONF_PATH    "/etc/systemd/network/"
#define NETWORK_CONF_FILE    "network.zip"
#define IPMI_CONF_PATH       ""
#define IPMI_CONF_FILE       ""
#define LDAP_CONF_PATH       "/etc/nslcd.conf"
#define LDAP_CONF_FILE       "nslcd.conf"

// D-Bus root for backup restore
constexpr auto backupRestoreRoot = "/xyz/openbmc_project/Backup";

using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::phosphor::logging::report;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using IfcBase = sdbusplus::xyz::openbmc_project::Backup::server::BackupRestore;

namespace fs = std::filesystem;

class BackupImp : IfcBase
{
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
        BackupImp(const BackupImp&) = delete;
        BackupImp& operator=(const BackupImp&) = delete;
        BackupImp(BackupImp&&) = delete;
        BackupImp& operator=(BackupImp&&) = delete;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         */
        BackupImp(sdbusplus::bus_t& bus, const char* path) :
            IfcBase(bus, path)
        {
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
	  fs::create_directories("backup/" + fileName);

	  //copy all the conf files to the folder
	  if(IfcBase::backupFlags().find('N') != std::string::npos)
	  {
	    executeCmd("/usr/bin/zip","/tmp/backup/network.zip",(std::string("/tmp/backup/") + NETWORK_CONF_PATH).c_str());
	    fs::copy_file(LDAP_CONF_PATH,"backup/" + fileName + "/" + "network.zip");
	    backupExist = true;
	  }
	  if(IfcBase::backupFlags().find('I') != std::string::npos)
	  {
	    fs::copy_file(IPMI_CONF_PATH,"backup/" + fileName + "/" + IPMI_CONF_FILE);
	    backupExist = true;
	  }
	  if(IfcBase::backupFlags().find('L') != std::string::npos)
	  {
	    fs::copy_file(LDAP_CONF_PATH,"backup/" + fileName + "/" + LDAP_CONF_FILE);
	    backupExist = true;
	  }
	  if(backupExist == false)
	  {
	    return std::string{"dev/null"};
	  }
	  
	  //zip the file
	  executeCmd("/usr/bin/zip",("/tmp/backup/" + fileName + ".zip").c_str(),("/tmp/backup/" + fileName).c_str());
	  
	  return ("/tmp/backup/" + fileName + ".zip"); 
	}

        /** Method: Restore Backup file
	 *  @brief Implementation Restore Backup file
         *  @param[in] fileName - name of backup file
         */
        bool restoreBackup(std::string fileName) override
        {
	  std::ofstream fpchassis;

	  //check if backup folder exists
	  if(!fs::exists("/tmp/restore"))
	    {
	      return false;
	    }
	  else if (!fs::exists("/tmp/restore/" + fileName))
	    {	
	      return false;
	    }

	  //unzip the file with option overwrite files
	  executeCmd("/usr/bin/unzip","-o",("/tmp/restore/" + fileName).c_str());
	  
	  return true; 
	}
  
        /** Property: backup Flags
	 *  @brief 
         *  @param[in] value - new value of the property
         */
        std::string backupFlags(std::string value) override
        {
	  FILE *fpchassis = fopen("/tmp/chassis.tmp","a+");
	  fprintf(fpchassis,"Set Property backupFlags %s\n",value.c_str());
	  fclose(fpchassis);
	  
	  std::string val;

	  try
	  {
	    if (value == IfcBase::backupFlags())
	    {
	      return value;
	    }
	    val = IfcBase::backupFlags(value);
	  }
	  catch (const std::exception& e)
	  {
	      log<level::ERR>(e.what());
	      elog<InternalFailure>();
	  }
	  return val;
        }
};

int main(int argc, char** argv)
{

  if(0)
    {
      argc = argc;
      argv = argv;
    }
  
  auto bus = sdbusplus::bus::new_default();

  // Claim the bus now
  bus.request_name("xyz.openbmc_project.Backup");
  
  sdbusplus::server::manager_t objManager(bus, backupRestoreRoot);
  
  BackupImp backupManager(bus, backupRestoreRoot);
    
  // Wait for client request
  bus.process_loop();


  
  return -1;
}
