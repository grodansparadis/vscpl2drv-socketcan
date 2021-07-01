// socketcan.cpp: implementation of the CSocketcan class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2020 Ake Hedman,
// Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Different on Kernel 2.6 and cansocket examples
// currently using locally from can-utils
// TODO remove include from makefile when they are in sync
#include <linux/can.h>
#include <linux/can/raw.h>

#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <expat.h>

#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscphelper.h>
#include <vscpremotetcpif.h>

#include "socketcan.h"
#include "vscpl2drv-socketcan.h"

#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <string>

// Buffer for XML parser
#define XML_BUFF_SIZE 10000

#include <json.hpp> // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

// https://github.com/nlohmann/json
using json = nlohmann::json;
using namespace kainjow::mustache;

// Forward declaration
void *
workerThread(void *pData);

//////////////////////////////////////////////////////////////////////
// CSocketcan
//

CSocketcan::CSocketcan()
{
  m_bDebug       = false;
  m_bWriteEnable = false;
  m_bQuit        = false;
  m_interface    = "vcan0";
  m_flags        = 0;

  vscp_clearVSCPFilter(&m_filterIn);  // Accept all events
  vscp_clearVSCPFilter(&m_filterOut); // Send all events

  sem_init(&m_semSendQueue, 0, 0);
  sem_init(&m_semReceiveQueue, 0, 0);

  pthread_mutex_init(&m_mutexSendQueue, NULL);
  pthread_mutex_init(&m_mutexReceiveQueue, NULL);

  // Init pool
  spdlog::init_thread_pool(8192, 1);

  // Flush log every five seconds
  spdlog::flush_every(std::chrono::seconds(5));

  auto console = spdlog::stdout_color_mt("console");
  // Start out with level=info. Config may change this
  console->set_level(spdlog::level::debug);
  console->set_pattern("[vscpl2drv-websrv] [%^%l%$] %v");
  spdlog::set_default_logger(console);

  console->debug("Starting the vscpl2drv-websrv...");

  m_bConsoleLogEnable = true;
  m_consoleLogLevel   = spdlog::level::info;
  m_consoleLogPattern = "[vscpl2drv-tcpiplink %c] [%^%l%$] %v";

  m_bEnableFileLog   = true;
  m_fileLogLevel     = spdlog::level::info;
  m_fileLogPattern   = "[vscpl2drv-tcpiplink %c] [%^%l%$] %v";
  m_path_to_log_file = "/var/log/vscp/vscpl2drv-tcpiplink.log";
  m_max_log_size     = 5242880;
  m_max_log_files    = 7;
}

//////////////////////////////////////////////////////////////////////
// ~CSocketcan
//

CSocketcan::~CSocketcan()
{
  close();

  sem_destroy(&m_semSendQueue);
  sem_destroy(&m_semReceiveQueue);

  pthread_mutex_destroy(&m_mutexSendQueue);
  pthread_mutex_destroy(&m_mutexReceiveQueue);
}

// ----------------------------------------------------------------------------


//////////////////////////////////////////////////////////////////////
// open
//
//

bool
CSocketcan::open(std::string &path, const cguid &guid)
{
  // Set GUID
  m_guid = guid;

  // Save path to config file
  m_path = path;

  // Read configuration file
  if (!doLoadConfig()) {
    spdlog::error("Failed to load configuration file {}", path);
  }

  // start the workerthread
  if (pthread_create(&m_threadWork, NULL, workerThread, this)) {
    spdlog::critical("Failed to load configuration file [{}]", path);
    return false;
  }

  return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CSocketcan::close(void)
{
  // Do nothing if already terminated
  if (m_bQuit) {
    return;
  }

  m_bQuit = true; // terminate the thread
  pthread_join(m_threadWork, NULL);
}

// ----------------------------------------------------------------------------

int depth_hlo_parser = 0;

void
startHLOParser(void *data, const char *name, const char **attr)
{
  CHLO *pObj = (CHLO *) data;
  if (NULL == pObj) {
    return;
  }
}

void
endHLOParser(void *data, const char *name)
{
  depth_hlo_parser--;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// parseHLO
//

bool
CSocketcan::parseHLO(uint16_t size, uint8_t *inbuf, CHLO *phlo)
{
  // Check pointers
  if (NULL == inbuf) {
    spdlog::error("HLO parser: HLO in-buffer pointer is NULL.");
    return false;
  }

  if (NULL == phlo) {
    spdlog::error("HLO parser: HLO obj pointer is NULL.");
    return false;
  }

  if (!size) {
    spdlog::error("HLO parser: HLO buffer size is zero.");
    return false;
  }

  XML_Parser xmlParser = XML_ParserCreate("UTF-8");
  XML_SetUserData(xmlParser, this);
  XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

  void *buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

  // Copy in the HLO object
  memcpy(buf, inbuf, size);

  if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
    spdlog::error("Failed parse XML setup.");
    XML_ParserFree(xmlParser);
    return false;
  }

  XML_ParserFree(xmlParser);

  return true;
}



// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------

/////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CSocketcan::readEncryptionKey(const std::string &path)
{
  bool rv = false; // Be negative today

  try {
    std::string vscpkey;
    std::ifstream in(path, std::ifstream::in);
    std::stringstream strStream;
    strStream << in.rdbuf();
    vscpkey = strStream.str();
    vscp_trim(vscpkey);
    spdlog::get("logger")->debug("vscp.key [{}]", vscpkey.c_str());
    rv = vscp_hexStr2ByteArray(m_vscp_key, 32, vscpkey.c_str());
  }
  catch (...) {
    spdlog::get("logger")->error("Failed to read encryption key file [{}]", m_path.c_str());
  }

  return rv;
}

bool
CSocketcan::doLoadConfig(void)
{
  try {
    std::ifstream in(m_path, std::ifstream::in);
    in >> m_j_config;
  }
  catch (json::parse_error &e) {
    spdlog::critical("Failed to load/parse JSON configuration. message: {}, id: {}, pos: {} ", e.what(), e.id, e.byte);
    return false;
  }
  catch (...) {
    spdlog::critical("Unknown exception when loading JSON configuration.");
    return false;
  }

  spdlog::debug("Reading configuration from [{}]", m_path);

  // Logging
  if (m_j_config.contains("logging") && m_j_config["logging"].is_object()) {

    json j = m_j_config["logging"];

    // * * *  CONSOLE  * * *

    // Logging: console-log-enable
    if (j.contains("console-enable")) {
      try {
        m_bConsoleLogEnable = j["console-enable"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'console-enable' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-enable' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'console-enable' Defaults will be used.");
    }

    // Logging: console-log-level
    if (j.contains("console-level")) {
      std::string str;
      try {
        str = j["console-level"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'console-level' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-level' due to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_consoleLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_consoleLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_consoleLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_consoleLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_consoleLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_consoleLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_consoleLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("Failed to read LOGGING 'console-level' has invalid "
                      "value [{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'console-level' Defaults will be used.");
    }

    // Logging: console-log-pattern
    if (j.contains("console-pattern")) {
      try {
        m_consoleLogPattern = j["console-pattern"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'console-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'console-pattern' Defaults will be used.");
    }

    // * * *  FILE  * * *

    // Logging: file-log-enable
    if (j.contains("file-enable")) {
      try {
        m_bEnableFileLog = j["file-enable"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-enable' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-enable' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'file-enable' Defaults will be used.");
    }

    // Logging: file-log-level
    if (j.contains("file-log-level")) {
      std::string str;
      try {
        str = j["file-log-level"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-level' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-level' due to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_fileLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_fileLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_fileLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_fileLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_fileLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_fileLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_fileLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("Failed to read LOGGING 'file-log-level' has invalid value "
                      "[{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'file-log-level' Defaults will be used.");
    }

    // Logging: file-log-pattern
    if (j.contains("file-log-pattern")) {
      try {
        m_fileLogPattern = j["file-log-pattern"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'file-log-pattern' Defaults will be used.");
    }

    // Logging: file-log-path
    if (j.contains("file-log-path")) {
      try {
        m_path_to_log_file = j["file-log-path"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-path' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-path' due to unknown error.");
      }
    }
    else {
      spdlog::error(" Failed to read LOGGING 'file-log-path' Defaults will be used.");
    }

    // Logging: file-log-max-size
    if (j.contains("file-log-max-size")) {
      try {
        m_max_log_size = j["file-log-max-size"].get<uint32_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-max-size' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-max-size' due to unknown error.");
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'file-log-max-size' Defaults will be used.");
    }

    // Logging: file-log-max-files
    if (j.contains("file-log-max-files")) {
      try {
        m_max_log_files = j["file-log-max-files"].get<uint16_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-max-files' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-max-files' due to unknown error.");
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'file-log-max-files' Defaults will be used.");
    }

  } // Logging
  else {
    spdlog::error("No logging has been setup.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          Setup logger
  ///////////////////////////////////////////////////////////////////////////

  // Console log
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  if (m_bConsoleLogEnable) {
    console_sink->set_level(m_consoleLogLevel);
    console_sink->set_pattern(m_consoleLogPattern);
  }
  else {
    // If disabled set to off
    console_sink->set_level(spdlog::level::off);
  }

  // auto rotating =
  // std::make_shared<spdlog::sinks::rotating_file_sink_mt>("log_filename",
  // 1024*1024, 5, false);
  auto rotating_file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(m_path_to_log_file.c_str(), m_max_log_size, m_max_log_files);

  if (m_bEnableFileLog) {
    rotating_file_sink->set_level(m_fileLogLevel);
    rotating_file_sink->set_pattern(m_fileLogPattern);
  }
  else {
    // If disabled set to off
    rotating_file_sink->set_level(spdlog::level::off);
  }

  std::vector<spdlog::sink_ptr> sinks{ console_sink, rotating_file_sink };
  auto logger = std::make_shared<spdlog::async_logger>("logger",
                                                       sinks.begin(),
                                                       sinks.end(),
                                                       spdlog::thread_pool(),
                                                       spdlog::async_overflow_policy::block);
  // The separate sub loggers will handle trace levels
  logger->set_level(spdlog::level::trace);
  spdlog::register_logger(logger);

  // ------------------------------------------------------------------------

  // write
  if (m_j_config.contains("write")) {
    try {
      m_bWriteEnable = m_j_config["write"].get<bool>();
      spdlog::debug("bWriteEnable set to {}", m_bWriteEnable);
    }
    catch (const std::exception &ex) {
      spdlog::error("Failed to read 'write' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("Failed to read 'write' due to unknown error.");
    }
  }
  else {
    spdlog::error("Failed to read 'write' item from configuration file. "
                  "Defaults will be used.");
  }

  // VSCP key file
  if (m_j_config.contains("key-file") && m_j_config["key-file"].is_string()) {
    if (!readEncryptionKey(m_j_config["key-file"].get<std::string>())) {
      spdlog::warn("Failed to read VSCP key from file [{}]. Default key will "
                   "be used. Dangerous!",
                   m_j_config["key-file"].get<std::string>());
    }
    else {
      spdlog::debug("key-file {} read successfully", m_j_config["key-file"].get<std::string>());
    }
  }
  else {
    spdlog::warn("VSCP key file is not defined. Default key will be used. Dangerous!");
  }

  // Filter
  if (m_j_config.contains("filter") && m_j_config["filter"].is_object()) {

    json j = m_j_config["filter"];

    // IN filter
    if (j.contains("in-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'in-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'in-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read LOGGING 'in-filter' Defaults will be used.");
    }

    // IN mask
    if (j.contains("in-mask")) {
      try {
        std::string str = j["in-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'in-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'in-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'in-mask' Defaults will be used.");
    }

    // OUT filter
    if (j.contains("out-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'out-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'out-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'out-filter' Defaults will be used.");
    }

    // OUT mask
    if (j.contains("out-mask")) {
      try {
        std::string str = j["out-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'out-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'out-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'out-mask' Defaults will be used.");
    }
  }

  ///////////////////////////////////////////////////////////////////////
  //                           socketcan
  ///////////////////////////////////////////////////////////////////////

  // Remote
  if (m_j_config.contains("socketcan") && m_j_config["socketcan"].is_object()) {

    json j = m_j_config["socketcan"];

    if (j.contains("interface") && j["interface"].is_string()) {
      try {
        m_interface = j["interface"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'interface' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'interface' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'interface' Defaults will be used.");
    }

    if (j.contains("flags") && j["flags"].is_number()) {
      try {
        m_flags = j["flags"].get<short>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'port' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'port' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'port' Defaults will be used.");
    }
  }

  return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool
CSocketcan::addEvent2SendQueue(const vscpEvent *pEvent)
{
  pthread_mutex_lock(&m_mutexSendQueue);
  m_sendList.push_back((vscpEvent *) pEvent);
  sem_post(&m_semSendQueue);
  pthread_mutex_unlock(&m_mutexSendQueue);
  return true;
}

//////////////////////////////////////////////////////////////////////
//                Workerthread - CSocketcanWorkerTread
//////////////////////////////////////////////////////////////////////

void *
workerThread(void *pData)
{
  int sock;
  char devname[IFNAMSIZ + 1];
  fd_set rdfs;
  struct timeval tv;
  struct sockaddr_can addr;
  struct ifreq ifr;
  struct cmsghdr *cmsg;
  struct canfd_frame frame;
  char ctrlmsg[CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(__u32))];
  const int canfd_on = 1;

  CSocketcan *pObj = (CSocketcan *) pData;
  if (NULL == pObj) {
    spdlog::error("No object data supplied for worker thread");
    return NULL;
  }

  strncpy(devname, pObj->m_interface.c_str(), sizeof(devname) - 1);
  if (pObj->m_bDebug) {
    spdlog::debug("CWriteSocketCanTread: Interface: '{}'", ifname);
  }

  while (!pObj->m_bQuit) {

    sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) {

      if (ENETDOWN == errno) {
        sleep(1);
        continue;
      }

      spdlog::error("CReadSocketCanTread: Error while opening socket. Terminating!");
      break;
    }

    strcpy(ifr.ifr_name, devname);
    ioctl(sock, SIOCGIFINDEX, &ifr);

    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (pObj->m_bDebug) {
      spdlog::debug("using interface name '{}'.", ifr.ifr_name);
    }

    // try to switch the socket into CAN FD mode
    setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &canfd_on, sizeof(canfd_on));

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
      spdlog::error("CReadSocketCanTread: Error in socket bind. Terminating!");
      close(sock);
      sleep(2);
      continue;
    }

    bool bInnerLoop = true;
    while (!pObj->m_bQuit && bInnerLoop) {

      FD_ZERO(&rdfs);
      FD_SET(sock, &rdfs);

      tv.tv_sec  = 0;
      tv.tv_usec = 5000; // 5ms timeout

      int ret;
      if ((ret = select(sock + 1, &rdfs, NULL, NULL, &tv)) < 0) {
        // Error
        if (ENETDOWN == errno) {
          // We try to get contact with the net
          // again if it goes down
          bInnerLoop = false;
        }
        else {
          pObj->m_bQuit = true;
        }
        continue;
      }

      if (ret) {

        // There is data to read

        ret = read(sock, &frame, sizeof(struct can_frame));
        if (ret < 0) {
          if (ENETDOWN == errno) {
            // We try to get contact with the net
            // again if it goes down
            bInnerLoop = false;
            sleep(2);
          }
          else {
            pObj->m_bQuit = true;
          }
          continue;
        }

        // Must be Extended
        if (!(frame.can_id & CAN_EFF_FLAG)) {
          continue;
        }

        // Mask of control bits
        frame.can_id &= CAN_EFF_MASK;

        vscpEvent *pEvent = new vscpEvent();
        if (NULL != pEvent) {

          // This can lead to level I frames having to
          // much data. Later code will handel this case.
          pEvent->pdata = new uint8_t[frame.len];
          if (NULL == pEvent->pdata) {
            delete pEvent;
            continue;
          }

          // GUID will be set to GUID of interface
          // by driver interface with LSB set to nickname
          memcpy(pEvent->GUID, pObj->m_guid.getGUID(), 16);
          pEvent->GUID[VSCP_GUID_LSB] = frame.can_id & 0xff;

          // Set VSCP class
          pEvent->vscp_class = vscp_getVscpClassFromCANALid(frame.can_id);

          // Set VSCP type
          pEvent->vscp_type = vscp_getVscpTypeFromCANALid(frame.can_id);

          // Copy data if any
          pEvent->sizeData = frame.len;
          if (frame.len) {
            memcpy(pEvent->pdata, frame.data, frame.len);
          }

          if (vscp_doLevel2Filter(pEvent, &pObj->m_filterIn)) {
            pthread_mutex_lock(&pObj->m_mutexReceiveQueue);
            pObj->m_receiveList.push_back(pEvent);
            sem_post(&pObj->m_semReceiveQueue);
            pthread_mutex_unlock(&pObj->m_mutexReceiveQueue);
          }
          else {
            vscp_deleteEvent(pEvent);
          }
        }
      }
      else {

        // Check if there is event(s) to send
        if (pObj->m_sendList.size()) {

          // Yes there are data to send
          // So send it out on the CAN bus

          pthread_mutex_lock(&pObj->m_mutexSendQueue);
          vscpEvent *pEvent = pObj->m_sendList.front();
          pObj->m_sendList.pop_front();
          pthread_mutex_unlock(&pObj->m_mutexSendQueue);

          if (NULL == pEvent)
            continue;

          // Class must be a Level I class or a Level II
          // mirror class
          if (pEvent->vscp_class < 512) {
            frame.can_id = vscp_getCANALidFromEvent(pEvent);
            frame.can_id |= CAN_EFF_FLAG; // Always extended
            if (0 != pEvent->sizeData) {
              frame.len = (pEvent->sizeData > 8 ? 8 : pEvent->sizeData);
              memcpy(frame.data, pEvent->pdata, frame.len);
            }
          }
          else if (pEvent->vscp_class < 1024) {
            pEvent->vscp_class -= 512;
            frame.can_id = vscp_getCANALidFromEvent(pEvent);
            frame.can_id |= CAN_EFF_FLAG; // Always extended
            if (0 != pEvent->sizeData) {
              frame.len = ((pEvent->sizeData - 16) > 8 ? 8 : pEvent->sizeData - 16);
              memcpy(frame.data, pEvent->pdata + 16, frame.len);
            }
          }

          // Remove the event
          pthread_mutex_lock(&pObj->m_mutexSendQueue);
          vscp_deleteEvent(pEvent);
          pthread_mutex_unlock(&pObj->m_mutexSendQueue);

          // Write the data
          int nbytes = write(sock, &frame, sizeof(struct can_frame));

        } // event to send

      } // No data to read

    } // Inner loop

    // Close the socket
    close(sock);

  } // Outer loop

  return NULL;
}
