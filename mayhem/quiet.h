#pragma once
#include "Log.h"

// libi2pd's logger queues every message for a writer thread that never runs here, so unbounded growth
// would hit libFuzzer's RSS limit; drop all messages instead.
inline void QuietLogs () { i2p::log::Logger ().SetLogLevel ("none"); }
