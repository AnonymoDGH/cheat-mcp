#include "cheatmcp.hpp"

int main() {
    // Elevate our token as far as we can for cross-process access.
    cmcp::enable_debug_privilege();

    // Build the tool surface and start the background freeze/watch worker.
    cmcp::register_all_tools();
    cmcp::runtime_start();

    int rc = cmcp::run_server();

    cmcp::runtime_stop();
    return rc;
}
