/*
* Semaphore
* (C) 2013 Joel Low
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifdef SOUP_BUILD
module;
#include <mutex>

#define SOUP_MACRO_ONLY
#include <botan/build.h>
module Botan;
#else

#include <botan/internal/semaphore.h>

#endif

// Based on code by Pierre Gaston (http://p9as.blogspot.com/2012/06/c11-semaphores.html)

namespace Botan {

void Semaphore::release(size_t n)
   {
   for(size_t i = 0; i != n; ++i)
      {
      std::lock_guard<std::mutex> lock(m_mutex);

      if(m_value++ < 0)
         {
         ++m_wakeups;
         m_cond.notify_one();
         }
      }
   }

void Semaphore::acquire()
   {
   std::unique_lock<std::mutex> lock(m_mutex);
   if(m_value-- <= 0)
       {
       m_cond.wait(lock, [this] { return m_wakeups > 0; });
       --m_wakeups;
       }
   }

}
