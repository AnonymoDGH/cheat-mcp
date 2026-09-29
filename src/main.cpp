#include "cheatmcp.hpp"
#include <string>

int main(int argc, char** argv) {
    // Elevated companion mode: `cheatmcp.exe --agent <pipe>`.
    if (argc >= 3 && std::string(argv[1]) == "--agent") {
        cmcp::run_agent_loop(argv[2]);
        return 0;
    }

    cmcp::enable_debug_privilege();
    cmcp::register_all_tools();
    cmcp::runtime_start();

    int rc = cmcp::run_server();

    cmcp::agent_shutdown();
    cmcp::runtime_stop();
    return rc;
}
