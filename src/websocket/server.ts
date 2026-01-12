import WS, { WebSocket } from "ws";
import express, { Express, Request } from "express";
import { verifyRequestSignature } from "../auth/authenticator";
import { Session } from "../common/session";
import { getPort } from "../common/environment-variables";
import { SecretService } from "../services/secret-service";

export class Server {
  private app: Express | undefined;
  private httpServer: any;
  private wsServer: any;
  private sessionMap: Map<WebSocket, Session> = new Map();
  private secretService = new SecretService();

  start() {
    console.log(`Starting server on port: ${getPort()}`);

    this.app = express();
    this.httpServer = this.app.listen(getPort());

    this.wsServer = new WebSocket.Server({
      noServer: true,
    });

    this.httpServer.on("upgrade", (request: Request, socket: any, head: any) => {
      console.log(`Received a connection request from ${request.url}.`);

      // ===== AUTH DEBUG (temporary) =====
      console.log("=== AUTH DEBUG HEADERS ===");
      console.log("url:", request.url);
      console.log("x-api-key:", request.headers["x-api-key"]);
      console.log("authorization:", request.headers["authorization"]);
      console.log("date:", request.headers["date"]);
      console.log("all headers:", request.headers);
      console.log("==========================");
      // ==================================

      verifyRequestSignature(request, this.secretService).then((verifyResult) => {
        if (verifyResult.code !== "VERIFIED") {
          console.log("Authentication failed, closing the connection.");
          socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
          socket.destroy();
          return;
        }

        this.wsServer.handleUpgrade(request, socket, head, (ws: WebSocket) => {
          console.log("Authentication was successful.");
          this.wsServer.emit("connection", ws, request);
        });
      });
    });

    this.wsServer.on("connection", (ws: WebSocket, request: Request) => {
      ws.on("close", () => {
        console.log("WebSocket connection closed.");
        this.deleteConnection(ws);
      });

      ws.on("error", (error: Error) => {
        console.log(`WebSocket Error: ${error}`);
        ws.close();
      });

      ws.on("message", (data: WS.RawData, isBinary: boolean) => {
        if (ws.readyState !== WebSocket.OPEN) return;

        const session = this.sessionMap.get(ws);

        if (!session) {
          const sessionId = request.headers["audiohook-session-id"] as string | undefined;

          // Fail fast with a clear message if session id is missing
          const dummySession = new Session(ws, sessionId ?? "missing-audiohook-session-id", request.url);
          console.log("Session does not exist.");
          dummySession.sendDisconnect("error", "Session does not exist.", {});
          return;
        }

        if (isBinary) {
          session.processBinaryMessage(data as Uint8Array);
        } else {
          session.processTextMessage(data.toString());
        }
      });

      this.createConnection(ws, request);
    });
  }

  private createConnection(ws: WebSocket, request: Request) {
    const existing = this.sessionMap.get(ws);
    if (existing) return;

    const sessionId = request.headers["audiohook-session-id"] as string | undefined;

    const session = new Session(ws, sessionId ?? "missing-audiohook-session-id", request.url);
    console.log("Creating a new session.");
    this.sessionMap.set(ws, session);
  }

  private deleteConnection(ws: WebSocket) {
    const session = this.sessionMap.get(ws);
    if (!session) return;

    try {
      session.close();
    } catch {
      // ignore
    }

    console.log("Deleting session.");
    this.sessionMap.delete(ws);
  }
}
