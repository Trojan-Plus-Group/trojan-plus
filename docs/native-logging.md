# Native log callback

`src/platform_exports.h` adds an optional C ABI; existing exports, C++ callback and
Android logcat tag `trojan`, priorities and formatting remain unchanged:

```c
typedef void (*trojan_log_callback)(const char* message, size_t length,
                                    int level, void* context);
int trojan_set_log_callback(trojan_log_callback callback, void* context);
```

- One process-wide subscriber. Setter replaces it; NULL unregisters. Return 0 means
  success and all previous calls have finished, so old context/delegate can be freed.
  Concurrent setters are serialized; last completed setter owns registration.
  Owners must serialize their lifecycle to avoid replacing each other.
- Return -1 from inside this callback means no change (including unregister).
  Return -2 means native synchronization failed; do not release previous ownership.
  No C++ exception escapes setter or delivery. Managed exceptions **must** be caught
  in managed code; native catch is not a managed-exception boundary.
- Delivery is synchronous on the logging thread, after platform output and before
  existing C++ callback. Calls are serialized, not dispatched to a UI thread.
  Callback must be short: copy/write or enqueue bounded data; do not wait for other
  threads that might log or register/unregister. Setter waits for active callback;
  calling it from a different thread and waiting for that thread inside callback
  would deadlock. Reentrant logging still reaches logcat but skips this C callback.
- Message pointer is read-only, valid only until callback returns. `length` is exact
  byte count, not UTF-16 characters; trailing NUL is excluded, embedded NUL included.
  No newline is added. Core text is UTF-8; external host/peer bytes are not validated,
  so decode with UTF-8 replacement fallback. No transcoding, truncation or allocation
  occurs in delivery. Levels: ALL=0, INFO=1, WARN=2, ERROR=3, FATAL=4, OFF=5.
  Existing log-level filter applies before delivery; registering does not enable logs.
- Registration survives `Log::reset`, native stop and restart. Explicitly unregister
  after `trojan_run_main` returns, before closing sink/unrooting delegate/unloading
  library. NULL registration is safe with no callback. Unregister can also run while
  native worker is active. No automatic registration from JNI, no retained `JNIEnv*`.
- This makes C callback lifetime safe, not all legacy logging configuration mutable
  concurrently: set `Log::level`, redirects and legacy C++ callback before workers
  start. Timestamp formatting uses per-thread streams. Existing legacy C++ callback
  must obey its original lifecycle and must not throw.

## Android managed integration

Use matching arm64-v8a/x86_64 libraries, register only with detailed logging enabled
in `:vpn_remote`, before starting native worker. P/Invoke `int` return, `IntPtr`
message/context and `UIntPtr` (or `nuint`) byte length; delegate uses Cdecl and returns
void. Root delegate/context until successful unregister. Copy exact bytes during
callback; use UTF-8 replacement fallback, not `PtrToStringAnsi` or NUL termination.
Catch all managed exceptions inside delegate. No Java attachment is needed for
reverse P/Invoke; JNI consumers instead need their own per-thread attach/global-ref
lifecycle, never the existing thread-local `g_android_java_env` on foreign threads.

Serialize writes to one app-private rolling file (app policy: 1 MiB), bounded queue
if asynchronous, flush accepted batches. On stop, wait for native worker completion,
unregister, drain/flush writer, close file, then release delegate and allow process
kill. If disabling detailed logging during run, unregister first, then drain/close.
Re-register explicitly on next enabled session. Do not edit/replace packaged app
artifacts without app owner's coordination.

## Privacy

TCP and QUIC authentication logs no longer print matched passwords. HTTP/3 and
HTTP/1 upstream error diagnostics no longer dump raw wire/body bytes. Detailed logs
still include destination/peer IPs, hostnames, DNS names, traffic sizes and errors;
treat exported files as sensitive browsing metadata. Do not log full configuration,
raw payloads, credentials or TLS key logs. Keep `ENABLE_SSL_KEYLOG` disabled; its
separate keylog file is not part of this callback. App export needs explicit privacy
confirmation, stopped-session bounded snapshots and private share permissions.

## Regression check

`python3 tests/test_log_callback.py` compiles production logger and allocator, tests
UTF-8/embedded NUL, level filtering, absent callback, reset, exceptions, reentrant
logging/setter rejection, blocking unregister and concurrent registration/delivery.
The same C++ source can be built with NDK and run with adb for Android/logcat checks.
