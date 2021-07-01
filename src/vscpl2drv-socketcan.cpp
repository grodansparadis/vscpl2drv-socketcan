// vscp2drv_socketcan.cpp : Defines the initialization routines for the DLL.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2021 Ake Hedman,
// Ake Hedman, Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#ifdef __GNUG__
//#pragma implementation
#endif

#include <list>
#include <map>
#include <string>

#include "stdio.h"
#include "stdlib.h"

#include "socketcan.h"
#include "version.h"
#include "vscpl2drv-socketcan.h"

#include <json.hpp> // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

// https://github.com/nlohmann/json
using json = nlohmann::json;
using namespace kainjow::mustache;

void
_init() __attribute__((constructor));
void
_fini() __attribute__((destructor));

void
_init() __attribute__((constructor));
void
_fini() __attribute__((destructor));

// This map holds driver handles/objects
static std::map<long, CSocketcan *> g_ifMap;

// Mutex for the map object
static pthread_mutex_t g_mapMutex;

////////////////////////////////////////////////////////////////////////////
// DLL constructor
//

void
_init()
{
  pthread_mutex_init(&g_mapMutex, NULL);
}

////////////////////////////////////////////////////////////////////////////
// DLL destructor
//

void
_fini()
{
  // If empty - nothing to do
  if (g_ifMap.empty())
    return;

  // Remove orphan objects

  LOCK_MUTEX(g_mapMutex);

  for (std::map<long, CSocketcan *>::iterator it = g_ifMap.begin(); it != g_ifMap.end(); ++it) {
    // std::cout << it->first << " => " << it->second << '\n';

    CSocketcan *pif = it->second;
    if (NULL != pif) {
      delete pif;
      pif = NULL;
    }
  }

  g_ifMap.clear(); // Remove all items

  UNLOCK_MUTEX(g_mapMutex);
  pthread_mutex_destroy(&g_mapMutex);
}

///////////////////////////////////////////////////////////////////////////////
// addDriverObject
//

long
addDriverObject(CSocketcan *pif)
{
  std::map<long, CSocketcan *>::iterator it;
  long h = 0;

  LOCK_MUTEX(g_mapMutex);

  // Find free handle
  while (true) {
    if (g_ifMap.end() == (it = g_ifMap.find(h)))
      break;
    h++;
  };

  g_ifMap[h] = pif;
  h += 1681;

  UNLOCK_MUTEX(g_mapMutex);

  return h;
}

///////////////////////////////////////////////////////////////////////////////
// getDriverObject
//

CSocketcan *
getDriverObject(long h)
{
  std::map<long, CSocketcan *>::iterator it;
  long idx = h - 1681;

  // Check if valid handle
  if (idx < 0)
    return NULL;

  it = g_ifMap.find(idx);
  if (it != g_ifMap.end()) {
    return it->second;
  }

  return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// removeDriverObject
//

void
removeDriverObject(long h)
{
  std::map<long, CSocketcan *>::iterator it;
  long idx = h - 1681;

  // Check if valid handle
  if (idx < 0)
    return;

  LOCK_MUTEX(g_mapMutex);
  it = g_ifMap.find(idx);
  if (it != g_ifMap.end()) {
    CSocketcan *pObj = it->second;
    if (NULL != pObj) {
      delete pObj;
      pObj = NULL;
    }
    g_ifMap.erase(it);
  }
  UNLOCK_MUTEX(g_mapMutex);
}

///////////////////////////////////////////////////////////////////////////////
//                         V S C P   D R I V E R -  A P I
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// VSCPOpen
//

extern "C" long
VSCPOpen(const char *pPathConfig, const char *pguid)
{
  long h = 0;

  CSocketcan *pdrvObj = new CSocketcan();
  if (NULL != pdrvObj) {

    cguid guid(pguid);
    std::string path = pPathConfig;
    if (path.length() && pdrvObj->open(path, guid)) {

      if (!(h = addDriverObject(pdrvObj))) {
        delete pdrvObj;
      }
    }
    else {
      delete pdrvObj;
    }
  }

  return h;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPClose
//

extern "C" int
VSCPClose(long handle)
{
  CSocketcan *pdrvObj = getDriverObject(handle);
  if (NULL == pdrvObj)
    return 0;
  pdrvObj->close();
  removeDriverObject(handle);

  return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPWrite
//

extern "C" int
VSCPWrite(long handle, const vscpEvent *pEvent, unsigned long timeout)
{
  CSocketcan *pdrvObj = getDriverObject(handle);
  if (NULL == pdrvObj) {
    return CANAL_ERROR_MEMORY;
  }

  pdrvObj->addEvent2SendQueue(pEvent);

  return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPRead
//

extern "C" int
VSCPRead(long handle, vscpEvent *pEvent, unsigned long timeout)
{
  int rv = 0;

  // Check pointer
  if (NULL == pEvent) {
    return CANAL_ERROR_PARAMETER;
  }

  CSocketcan *pdrvObj = getDriverObject(handle);
  if (NULL == pdrvObj) {
    return CANAL_ERROR_MEMORY;
  }

  if (-1 == (rv = vscp_sem_wait(&pdrvObj->m_semReceiveQueue, timeout))) {
    if (ETIMEDOUT == errno) {
      return CANAL_ERROR_TIMEOUT;
    }
    else if (EINTR == errno) {
      spdlog::error("[vscpl2drv-socketcan] Interrupted by a signal handler");
      return CANAL_ERROR_INTERNAL;
    }
    else if (EINVAL == errno) {
      spdlog::error("[vscpl2drv-socketcan] Invalid semaphore (timout)");
      return CANAL_ERROR_INTERNAL;
    }
    else if (EAGAIN == errno) {
      spdlog::error("[vscpl2drv-socketcan] Blocking error");
      return CANAL_ERROR_INTERNAL;
    }
    else {
      spdlog::error("[vscpl2drv-socketcan] Unknown error");
      return CANAL_ERROR_INTERNAL;
    }
  }

  pthread_mutex_lock(&pdrvObj->m_mutexReceiveQueue);
  vscpEvent *pLocalEvent = pdrvObj->m_receiveList.front();
  pdrvObj->m_receiveList.pop_front();
  pthread_mutex_unlock(&pdrvObj->m_mutexReceiveQueue);
  if (NULL == pLocalEvent) {
    return CANAL_ERROR_MEMORY;
  }

  vscp_copyEvent(pEvent, pLocalEvent);
  vscp_deleteEvent(pLocalEvent);

  return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// VSCPGetVersion
//

extern "C" unsigned long
VSCPGetVersion(void)
{
  unsigned long ver = MAJOR_VERSION << 24 | MINOR_VERSION << 16 | RELEASE_VERSION << 8 | BUILD_VERSION;
  return ver;
}