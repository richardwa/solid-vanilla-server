import express, { Router } from "express";
import type { NextFunction, Request, Response, Server } from "express";
import { apiPath, checkCredentials, parseBasicHeader } from "./auth.ts";

// Express scaffolding shared by the solid-vanilla apps: request logger,
// POST {apiPath}/login route, Basic-auth middleware, and a generic dispatch
// that maps every method of a ServerApi implementation to POST {apiPath}/key
// (parameters and result are JSON-serialized; the types come from the shared
// common/interface.ts so client and server stay in sync).

export type ApiConfig = {
  /** The app's API implementation; each method becomes POST {apiPath}/key. */
  serverImpl: Record<string, (...args: never[]) => Promise<unknown>>;
  /** Credential check used by /api/login and the auth middleware; defaults
   *  to users.yaml-based checkCredentials (see auth.ts). */
  checkCredentials?: (login: string, password: string) => Promise<boolean>;
};

const unauthorized = (res: Response) => {
  res.status(401).json({ error: "not authenticated" });
};

/** Express middleware: validate the Authorization: Basic header. */
export const basicAuth = (req: Request, res: Response, next: NextFunction) => {
  const credentials = parseBasicHeader(req.headers.authorization);
  if (!credentials) return unauthorized(res);
  void (async () => {
    const check = req.app.locals
      .checkCredentials as ApiConfig["checkCredentials"];
    if (check && (await check(credentials.login, credentials.password))) next();
    else unauthorized(res);
  })();
};

/** Wire logger + login route + auth middleware + API dispatch onto app. */
export const configureApi = (
  app: Server,
  { serverImpl, checkCredentials: check = checkCredentials }: ApiConfig,
) => {
  // @ts-ignore — express.json() is typed as RequestHandler on Application
  app.use(express.json());
  const logger = (req: Request, _res: Response, next: NextFunction) => {
    console.log(`[${req.method}] ${req.url}`);
    next();
  };
  app.use(logger);

  // Validates credentials only; the client keeps them and sends Basic auth.
  app.post(`${apiPath}/login`, async (req: Request, res: Response) => {
    const [login, password] =
      (req as Request & { body?: unknown[] }).body ?? [];
    const ok = await check(String(login ?? ""), String(password ?? ""));
    res.json({ ok, error: ok ? undefined : "invalid login or password" });
  });

  // stash the check for the middleware (app.locals is typed loosely)
  (app.locals as Record<string, unknown>).checkCredentials = check;
  app.use(apiPath, basicAuth);

  const routes = Router();
  Object.entries(serverImpl).forEach(([key, fn]) => {
    routes.post(`/${key}`, async (req: Request, res: Response) => {
      try {
        const reqParams = (req as Request & { body?: unknown[] }).body ?? [];
        const result = await (fn as (...a: unknown[]) => unknown)(...reqParams);
        res.json(result);
      } catch (err) {
        res
          .status(500)
          .json({ error: err instanceof Error ? err.message : String(err) });
      }
    });
  });
  app.use(apiPath, routes);
};
