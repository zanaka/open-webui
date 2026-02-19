import ctypes
import logging
import os

MCL_CURRENT = 1  # Lock all pages currently mapped into the address space
MCL_FUTURE = 2  # Lock pages that become mapped in the future

log = logging.getLogger("open_webui.memory_lock")


def enable_memory_lock() -> None:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)

    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    log.info(
        "System memory locked successfully via mlockall. "
        "Swap is disabled for this process."
    )
