#!/usr/bin/env python3
"""Build patched ngtcp2 in an isolated temp tree; check transport wire profiles."""
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run(args, check=True)


with tempfile.TemporaryDirectory(prefix="quic-chrome-") as directory:
    work = pathlib.Path(directory)
    source = work / "ngtcp2"
    shutil.copytree(ROOT / "ngtcp2" / "lib", source / "lib")
    # Patches need only lib; build uses upstream CMake from original source copy.
    for name in ("CMakeLists.txt", "CMakeOptions.txt", "cmake", "crypto", "third-party", "examples", "tests"):
        item = ROOT / "ngtcp2" / name
        if item.is_dir():
            shutil.copytree(item, source / name)
        elif item.exists():
            shutil.copy2(item, source / name)
    for item in (ROOT / "ngtcp2").glob("*.in"):
        shutil.copy2(item, source / item.name)
    patch = work / "patch.cmake"
    patch.write_text(f'set(NGTCP2_PATCHED_DIR "{source}")\n'
                     f'include("{ROOT}/src/quic/ngtcp2_recovery.cmake")\n'
                     f'include("{ROOT}/src/quic/ngtcp2_fingerprint.cmake")\n')
    run("cmake", "-P", str(patch))
    build = work / "build"
    run("cmake", "-S", str(source), "-B", str(build), "-DENABLE_LIB_ONLY=ON",
        "-DENABLE_OPENSSL=OFF", "-DBUILD_TESTING=OFF", "-DENABLE_SHARED_LIB=OFF")
    run("cmake", "--build", str(build), "--target", "ngtcp2_static", "--parallel", "2")
    check = work / "check.c"
    check.write_text(r'''
#include <assert.h>
#include <string.h>
#include "ngtcp2_conn.h"
#include "ngtcp2_conv.h"
int main(void) {
  ngtcp2_conn conn = {0};
  uint8_t wire[1024], plain[1024], again[1024];
  const uint8_t *p, *end;
  uint64_t id, len;
  ngtcp2_ssize n, native;
  int seed, google, grease, changed = 0;
  ngtcp2_transport_params_default(&conn.local.transport_params);
  native = ngtcp2_transport_params_encode(plain, sizeof(plain), &conn.local.transport_params);
  n = ngtcp2_conn_encode_local_transport_params2(&conn, wire, sizeof(wire));
  assert(n == native && !memcmp(wire, plain, (size_t)n));
  conn.local.transport_params.tp_chrome_fingerprint = 1;
  for (seed = 1; seed <= 32; ++seed) {
    ngtcp2_pcg32_init(&conn.pcg, (uint64_t)seed);
    n = ngtcp2_conn_encode_local_transport_params2(&conn, wire, sizeof(wire));
    assert(n > native);
    assert(n == ngtcp2_conn_encode_local_transport_params2(&conn, NULL, 0));
    assert(n == ngtcp2_conn_encode_local_transport_params2(&conn, again, sizeof(again)));
    assert(!memcmp(wire, again, (size_t)n));
    assert(ngtcp2_conn_encode_local_transport_params2(&conn, again, (size_t)n - 1) == NGTCP2_ERR_NOBUF);
    google = grease = 0;
    p = wire; end = wire + n;
    while (p < end) {
      p = ngtcp2_get_uvarint(&id, p);
      p = ngtcp2_get_uvarint(&len, p);
      assert(len <= (uint64_t)(end - p));
      if (id == 0x3128) { assert(len == 4 && !memcmp(p, "ORIG", 4)); ++google; }
      if (id >= 27 && (id - 27) % 31 == 0) { assert(len <= 8); ++grease; }
      p += len;
    }
    assert(p == end && google == 1 && grease == 1);
    if (seed > 1 && memcmp(plain, wire, (size_t)n)) changed = 1;
    memcpy(plain, wire, (size_t)n);
  }
  assert(changed);
  conn.server = 1;
  n = ngtcp2_conn_encode_local_transport_params2(&conn, wire, sizeof(wire));
  assert(n == native);
  return 0;
}
''')
    run("cc", "-std=c11", "-I" + str(source / "lib"),
        "-I" + str(source / "lib/includes"), "-I" + str(build / "lib/includes"),
        str(check), str(build / "lib/libngtcp2.a"), "-o", str(work / "check"))
    run(str(work / "check"))
print("QUIC Chrome transport regression passed")
