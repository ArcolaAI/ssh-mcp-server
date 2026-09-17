import { registerExecuteCommandTool } from "./execute-command.js";
import { registerUploadTool } from "./upload.js";
import { registerDownloadTool } from "./download.js";
import { registerListServersTool } from "./list-servers.js";
/**
 * Register all tools
 * @param server MCP server instance
 */
export function registerAllTools(server) {
    registerExecuteCommandTool(server);
    registerUploadTool(server);
    registerDownloadTool(server);
    registerListServersTool(server);
}
