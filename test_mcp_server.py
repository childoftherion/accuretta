import sys
import json

def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except:
            continue
            
        method = req.get("method")
        req_id = req.get("id")
        
        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"}
                }
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [{
                        "name": "echo_test",
                        "description": "A simple echo tool to test MCP",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"message": {"type": "string"}},
                            "required": ["message"]
                        }
                    }]
                }
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            
        elif method == "tools/call":
            params = req.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            
            if name == "echo_test":
                msg = args.get("message", "")
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Echoed from MCP: {msg}"}]
                    }
                }
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
                
if __name__ == "__main__":
    main()
