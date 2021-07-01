// socketcan.h: interface for the socketcan class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
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

#if !defined(                                                                  \
  VSCPSOCKETCAN_L2_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
#define VSCPSOCKETCAN_L2_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_

#define _POSIX

#include <list>
#include <string>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <canal.h>
#include <canal_macro.h>
#include <guid.h>
#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscpdatetime.h>
#include <vscphelper.h>

#include <json.hpp>  // Needs C++11  -std=c++11

#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;



const uint16_t MAX_ITEMS_IN_QUEUE = 32000;

// Forward declarations

class CSocketcan
{
  public:

    const u_int32_t flag_fd_enable = 0x00008000; // FD frames will be handled

    /// Constructor
    CSocketcan();

    /// Destructor
    virtual ~CSocketcan();

    /*!
        Open
        @return True on success.
     */
    bool open(std::string &path, const cguid &guid);

    /*!
        Flush and close the log file
     */
    void close(void);

    /*!
    Parse HLO object
  */
  bool parseHLO(uint16_t size, uint8_t *inbuf, CHLO *phlo);

  /*!
    Handle high level object
  */
  bool handleHLO(vscpEvent *pEvent);

  /*!
    Read encryption key
    @param path Path to file containing key
    @return true on success, false on failure
  */
  bool readEncryptionKey(const std::string &path);

  /*!
    Load configuration if allowed to do so
    @return true on success, false on failure
  */
  bool doLoadConfig(void);

  /*!
    Save configuration if allowed to do so
  */
  bool doSaveConfig(void);

    /*!
            Add event to send queue
     */
    bool addEvent2SendQueue(const vscpEvent *pEvent);

  public:
  
    /// Parsed Config file
    json m_j_config;

    // ------------------------------------------------------------------------

    // * * * Configuration    

    /// enable/disable debug output
    bool m_bDebug;

    /// Path to configuration file
    std::string m_path;

    /// True if config is remote writable
    bool m_bWriteEnable;
    
    /// interface to listen on
    std::string m_interface;

    /// Driver flags
    uint32_t m_flags;

    /////////////////////////////////////////////////////////
    //                      Logging
    /////////////////////////////////////////////////////////
    
    bool m_bEnableFileLog;                        // True to enable logging
    spdlog::level::level_enum m_fileLogLevel;     // log level
    std::string m_fileLogPattern;                 // log file pattern
    std::string m_path_to_log_file;               // Path to logfile      
    uint32_t m_max_log_size;                      // Max size for logfile before rotating occurs 
    uint16_t m_max_log_files;                     // Max log files to keep

    bool m_bConsoleLogEnable;                     // True to enable logging to console
    spdlog::level::level_enum m_consoleLogLevel;  // Console log level
    std::string m_consoleLogPattern;              // Console log pattern

    // ------------------------------------------------------------------------

    /// Run flag
    bool m_bQuit;

    /// Response timeout
    uint32_t m_responseTimeout;

    /// Filters for input/output
    vscpEventFilter m_filterIn;
    vscpEventFilter m_filterOut;

    /// Get GUID for this interface.
    cguid m_guid;

    /// The default random encryption key
    uint8_t m_vscp_key[32] = {
        0x2d, 0xbb, 0x07, 0x9a, 0x38, 0x98, 0x5a, 0xf0, 0x0e, 0xbe, 0xef, 0xe2, 0x2f, 0x9f, 0xfa, 0x0e,
        0x7f, 0x72, 0xdf, 0x06, 0xeb, 0xe4, 0x45, 0x63, 0xed, 0xf4, 0xa1, 0x07, 0x3c, 0xab, 0xc7, 0xd4
    };

    /// Pointer to worker threads
    pthread_t m_threadWork;

    std::list<vscpEvent *> m_sendList;
    std::list<vscpEvent *> m_receiveList;

    /*!
      Event object to indicate that there is an event in the output queue
    */
    sem_t m_semSendQueue;
    sem_t m_semReceiveQueue;

    // Mutex to protect the output queue
    pthread_mutex_t m_mutexSendQueue;
    pthread_mutex_t m_mutexReceiveQueue;
};



#endif // !defined(VSCPSOCKETCAN_L2_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
